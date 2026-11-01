"""Bounded production WSGI serving. Development serving must be explicit."""
def serve_dashboard(app, host="127.0.0.1", port=5000, *, development=False):
    if development:
        app.run(host=host, port=port, debug=False, threaded=True)
        return
    from waitress import serve
    serve(app, host=host, port=port, threads=16, connection_limit=128,
          channel_timeout=30, max_request_body_size=65536,
          expose_tracebacks=False, clear_untrusted_proxy_headers=True)
