"""Exercise real HTTP, TLS interception, WebSocket and upstream forwarding."""
import asyncio
import os
import re
from pathlib import Path
import ssl
import tempfile
from aiohttp import web, ClientSession


async def main():
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        processes = []
        logs = []
        async def spawn(*args):
            log = open(root / f'process-{len(logs)}.log', 'w+')
            logs.append(log)
            process = await asyncio.create_subprocess_exec(*args, stdout=log, stderr=log, env={**os.environ, 'PYTHONUNBUFFERED': '1'})
            processes.append(process)
            return process
        runner = None
        try:
            # Use a dedicated local upstream proxy for the entire smoke test.
            await spawn('.venv/bin/mitmdump', '--listen-host', '127.0.0.1', '-p', '19090',
                        '--set', f'confdir={root / "upstream"}')
            for _ in range(100):
                if (root / 'upstream/mitmproxy-ca-cert.pem').exists():
                    break
                await asyncio.sleep(.1)
            await spawn('.venv/bin/xmproxy', '--port', '18080', '--web-host', '0.0.0.0', '--web-port', '18081',
                        '--data-dir', str(root / 'client'), '--upstream-only', '--upstream', 'http://127.0.0.1:19090',
                        '--record', str(root / 'flows.mitm'), '--trusted-ca', str(root / 'upstream/mitmproxy-ca-cert.pem'))
            ca = root / 'upstream/mitmproxy-ca-cert.pem'
            for _ in range(100):
                if ca.exists() and (root / 'client/mitmproxy-ca-cert.pem').exists():
                    break
                if any(p.returncode is not None for p in processes):
                    raise RuntimeError('proxy exited during startup')
                await asyncio.sleep(.1)
            # Upstream must trust the origin certificate; create an origin cert signed
            # by the upstream's local CA to keep TLS verification enabled throughout.
            from cryptography import x509
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import rsa
            from cryptography.x509.oid import NameOID
            import datetime
            bundle = (root / 'upstream/mitmproxy-ca.pem').read_bytes()
            key = serialization.load_pem_private_key(bundle, None)
            cert = x509.load_pem_x509_certificate(bundle)
            origin_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            now = datetime.datetime.now(datetime.timezone.utc)
            origin_cert = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'localhost')]))
                .issuer_name(cert.subject).public_key(origin_key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - datetime.timedelta(minutes=1)).not_valid_after(now + datetime.timedelta(days=1))
                .add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost')]), False).sign(key, hashes.SHA256()))
            (root / 'origin.pem').write_bytes(origin_cert.public_bytes(serialization.Encoding.PEM))
            (root / 'origin.key').write_bytes(origin_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
            # Restart upstream with an explicit trust root, then start a test origin.
            processes[0].terminate()
            await processes[0].wait()
            await spawn('.venv/bin/mitmdump', '--listen-host', '127.0.0.1', '-p', '19090',
                        '--set', f'confdir={root / "upstream"}', '--set', f'ssl_verify_upstream_trusted_ca={ca}')
            for _ in range(100):
                try:
                    reader, writer = await asyncio.open_connection('127.0.0.1', 19090)
                    writer.close()
                    await writer.wait_closed()
                    break
                except OSError:
                    await asyncio.sleep(.1)
            app = web.Application()
            async def hello(request):
                return web.Response(text='xmproxy-ok')
            async def websocket(request):
                ws = web.WebSocketResponse()
                await ws.prepare(request)
                async for message in ws:
                    await ws.send_str('echo:' + message.data)
                return ws
            app.router.add_get('/', hello)
            app.router.add_get('/ws', websocket)
            runner = web.AppRunner(app)
            await runner.setup()
            await web.TCPSite(runner, '127.0.0.1', 18082).start()
            server_tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            server_tls.load_cert_chain(root / 'origin.pem', root / 'origin.key')
            await web.TCPSite(runner, '127.0.0.1', 18443, ssl_context=server_tls).start()
            client_tls = ssl.create_default_context(cafile=str(root / 'client/mitmproxy-ca-cert.pem'))
            proxy = 'http://127.0.0.1:18080'
            async with ClientSession() as session:
                for _ in range(100):
                    try:
                        logs[1].seek(0)
                        token = re.search(r'\?token=([a-zA-Z0-9]+)', logs[1].read())
                        if not token:
                            await asyncio.sleep(.1)
                            continue
                        async with session.get('http://127.0.0.1:18081/?token=' + token.group(1)) as response:
                            assert response.status == 200
                        break
                    except OSError:
                        await asyncio.sleep(.1)
                for url in ('http://localhost:18082/', 'https://localhost:18443/'):
                    async with session.get(url, proxy=proxy, ssl=client_tls) as response:
                        body = await response.text()
                        assert response.status == 200, (url, response.status, body)
                        assert body == 'xmproxy-ok'
                for url in ('http://localhost:18082/ws', 'https://localhost:18443/ws'):
                    async with session.ws_connect(url, proxy=proxy, ssl=client_tls) as ws:
                        await ws.send_str('debug')
                        message = await asyncio.wait_for(ws.receive(), 5)
                        assert message.data == 'echo:debug'
            print('PASS: web UI, HTTP, HTTPS MITM, WS and WSS through upstream proxy')
        finally:
            if runner:
                await runner.cleanup()
            for process in processes:
                if process.returncode is None:
                    process.terminate()
                    await process.wait()
            for log in logs:
                log.seek(0)
                content = log.read()
                log.close()
                if 'Traceback' in content or 'error' in content.lower():
                    print(re.sub(r'\?token=[a-zA-Z0-9]+', '?token=[redacted]', content))
        from mitmproxy.io import FlowReader
        with open(root / 'flows.mitm', 'rb') as stream:
            flows = list(FlowReader(stream).stream())
        assert len(flows) == 4, len(flows)
        assert sum(f.websocket is not None for f in flows) == 2
        print('PASS: recorded four flows, including two WebSocket conversations')


asyncio.run(asyncio.wait_for(main(), 45))
