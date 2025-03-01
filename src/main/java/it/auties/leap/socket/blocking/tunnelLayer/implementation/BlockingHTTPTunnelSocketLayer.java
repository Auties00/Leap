package it.auties.leap.socket.blocking.tunnelLayer.implementation;

import it.auties.leap.http.response.HttpResponse;
import it.auties.leap.http.response.HttpResponseHandler;
import it.auties.leap.http.response.HttpResponseStatusCode;
import it.auties.leap.http.blocking.BlockingHttpResponseDecoder;
import it.auties.leap.socket.SocketException;
import it.auties.leap.socket.blocking.applicationLayer.BlockingSocketApplicationLayer;
import it.auties.leap.socket.blocking.tunnelLayer.BlockingSocketTunnelLayer;
import it.auties.leap.socket.blocking.tunnelLayer.BlockingSocketTunnelLayerFactory;

import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.ByteBuffer;
import java.util.Base64;

public final class BlockingHTTPTunnelSocketLayer extends BlockingSocketTunnelLayer {
    private static final BlockingSocketTunnelLayerFactory FACTORY = BlockingHTTPTunnelSocketLayer::new;

    private final URI proxy;
    public BlockingHTTPTunnelSocketLayer(BlockingSocketApplicationLayer applicationLayer, URI proxy) {
        super(applicationLayer);
        this.proxy = proxy;
    }

    public static BlockingSocketTunnelLayerFactory factory() {
        return FACTORY;
    }

    @Override
    public void connect(InetSocketAddress address) {
        applicationLayer.connect(new InetSocketAddress(proxy.getHost(), proxy.getPort()));
        sendAuthentication(address);
        readAuthenticationResponse(address);
    }

    private void readAuthenticationResponse(InetSocketAddress address) {
        try {
            var decoder = new BlockingHttpResponseDecoder(applicationLayer);
            var result = decoder.readResponse(HttpResponseHandler.ofString());
            onAuthenticationResponse(result, address);
        }catch (Throwable throwable) {
            throw new SocketException("HTTP : Cannot read authentication response", throwable);
        }
    }

    private void onAuthenticationResponse(HttpResponse<String> result, InetSocketAddress address) {
        switch (result) {
            case HttpResponse.Result<String> response -> {
                if (response.statusCode() != HttpResponseStatusCode.ok()) {
                    throw new SocketException("HTTP : Cannot connect to value, status code " + response.statusCode());
                }

                applicationLayer        .setAddress(address);
            }

            case HttpResponse.Redirect<String> _ -> throw new SocketException("HTTP : Invalid redirect while connecting to value");
        };
    }

    private void sendAuthentication(InetSocketAddress endpoint) {
        var builder = new StringBuilder();
        builder.append("CONNECT ")
                .append(endpoint.getHostName())
                .append(":")
                .append(endpoint.getPort())
                .append(" HTTP/1.1\r\n");
        builder.append("host: ")
                .append(endpoint.getHostName())
                .append("\r\n");
        var authInfo = proxy.getUserInfo();
        if (authInfo != null) {
            builder.append("value-authorization: Basic ")
                    .append(Base64.getEncoder().encodeToString(authInfo.getBytes()))
                    .append("\r\n");
        }
        builder.append("\r\n");
        applicationLayer.write(ByteBuffer.wrap(builder.toString().getBytes()));
    }
}
