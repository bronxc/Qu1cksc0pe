"""Bounded script requests using Frida's public message transport.

Some Frida Python releases do not cancel exports_sync waits. Keep the wait in
our own thread instead of leaving an unbounded RPC worker behind on timeout.
"""
import threading
import time
import uuid
import re


DISPATCHER = r'''
;(function receiveRequest() {
    recv('sc0pe-request', function (request) {
        receiveRequest();
        Promise.resolve().then(function () {
            const fn = rpc.exports[request.method];
            if (typeof fn !== 'function') throw new Error('Unknown monitor request');
            return fn.apply(null, request.args);
        }).then(function (value) {
            const binary = value instanceof ArrayBuffer;
            send({type: 'sc0pe-reply', id: request.id, value: binary ? null : value,
                  binary: binary}, binary ? value : null);
        }, function (error) {
            send({type: 'sc0pe-reply', id: request.id, error: String(error)});
        });
    });
})();
'''


def request(script, method, args=(), *, timeout=5, stop=None, post=None):
    """Wait at most timeout seconds; ignore late replies after removing handlers."""
    request_id = uuid.uuid4().hex
    finished = threading.Event()
    result = {}

    def on_message(message, data):
        payload = message.get('payload')
        if (message.get('type') == 'send' and isinstance(payload, dict)
                and payload.get('type') == 'sc0pe-reply' and payload.get('id') == request_id):
            result.update(payload)
            if payload.get('binary'):
                result['value'] = data
            finished.set()

    def on_destroyed():
        result['error'] = 'Script was destroyed during request'
        finished.set()

    script.on('message', on_message)
    script.on('destroyed', on_destroyed)
    deadline = time.monotonic() + timeout
    try:
        if stop is not None and stop.is_set():
            raise RuntimeError('Analysis was stopped')
        js_method = re.sub(r'_([a-z])', lambda match: match[1].upper(), method)
        message = {'type': 'sc0pe-request', 'id': request_id, 'method': js_method, 'args': list(args)}
        if post is None:
            script.post(message)
        else:
            post(script.post, message, timeout=timeout)
        while not finished.is_set():
            if stop is not None and stop.is_set():
                raise RuntimeError('Analysis was stopped')
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(f'Android agent request {method} exceeded {timeout:g} seconds')
            finished.wait(min(remaining, 0.05))
        if 'error' in result:
            raise RuntimeError(result['error'])
        return result.get('value')
    finally:
        script.off('message', on_message)
        script.off('destroyed', on_destroyed)
