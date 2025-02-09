package it.auties.leap.http;

import it.auties.leap.http.async.client.AsyncHttpClient;
import it.auties.leap.http.blocking.client.BlockingHttpClient;

public sealed interface HttpClient permits AsyncHttpClient, BlockingHttpClient {
}
