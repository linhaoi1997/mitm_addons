from mitmproxy import proxy, options
from mitmproxy.tools.dump import DumpMaster
from AutoReplayFlows.auto_play_flows import addon


def start():
    opts = options.Options(listen_host='127.0.0.1', listen_port=8090)
    # opts.add_option("body_size_limit", int, 0, "")
    # opts.add_option("keep_host_header", bool, True, "")
    #  opts.add_option("mode", str, "upstream:http://127.0.0.1:8118", "")
    # opts.add_option("ssl_insecure", bool, True, "")
    pconf = proxy.config.ProxyConfig(opts)
    m = DumpMaster(opts)
    m.server = proxy.server.ProxyServer(pconf)
    m.addons.add(addon)

    try:
        m.run()
    except KeyboardInterrupt:
        m.shutdown()


if __name__ == '__main__':
    from mitmproxy.tools._main import run
    run()
