/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH
 * under one or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information regarding copyright
 * ownership. Camunda licenses this file to you under the Apache License,
 * Version 2.0; you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.camunda.connect.usehttpclient.impl;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import jdk.nashorn.internal.parser.JSONParser;
import org.apache.http.Consts;
import org.apache.http.HttpEntity;
import org.apache.http.NameValuePair;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.ResponseHandler;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpDelete;
import org.apache.http.client.methods.HttpEntityEnclosingRequestBase;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpHead;
import org.apache.http.client.methods.HttpOptions;
import org.apache.http.client.methods.HttpPatch;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpPut;
import org.apache.http.client.methods.HttpRequestBase;
import org.apache.http.client.methods.HttpTrace;
import org.apache.http.entity.InputStreamEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.camunda.connect.usehttpclient.HttpBaseRequest;
import org.camunda.connect.usehttpclient.HttpResponse;
import org.camunda.connect.impl.AbstractConnector;

public abstract class AbstractHttpConnector<Q extends HttpBaseRequest<Q, R>, R extends HttpResponse> extends AbstractConnector<Q, R> {

  protected static HttpConnectorLogger LOG = HttpLogger.HTTP_LOGGER;

  protected CloseableHttpClient httpClient;
  protected final Charset charset;

  public AbstractHttpConnector(String connectorId) {
    super(connectorId);
    httpClient = createClient();
    charset = StandardCharsets.UTF_8;
  }

  protected CloseableHttpClient createClient() {
    return HttpClients.createSystem();
  }

  public CloseableHttpClient getHttpClient() {
    return httpClient;
  }

  public void setHttpClient(CloseableHttpClient httpClient) {
    this.httpClient = httpClient;
  }

  @Override
  public R execute(Q request) {
    try {
      String apiUseall = request.getApiUseall();
      String clientId = request.getClientId();
      String clientSecret = request.getClientSecret();
      if (apiUseall == null || apiUseall.isEmpty()) {
        throw new ClientProtocolException("Api do Useall não informado.");
      }
      if (clientId == null || clientId.isEmpty()) {
        throw new ClientProtocolException("Client ID não informado.");
      }
      if (clientSecret == null || clientSecret.isEmpty()) {
        throw new ClientProtocolException("Client Secret não informado.");
      }
      HttpPost httpPost = new HttpPost( apiUseall + "/api/token");
      List<NameValuePair> nvps = new ArrayList<NameValuePair>();
      nvps.add(new BasicNameValuePair("grant_type", "client_credentials"));
      nvps.add(new BasicNameValuePair("client_id", clientId));
      nvps.add(new BasicNameValuePair("client_secret", clientSecret));
      String nomeConexaoUseall = request.getNomeConexaoUseall();
      if (nomeConexaoUseall != null && !nomeConexaoUseall.isEmpty()) {
        nvps.add(new BasicNameValuePair("NomeConexao", nomeConexaoUseall));
      }
      httpPost.setEntity(new UrlEncodedFormEntity(nvps, Consts.UTF_8));

      ResponseHandler<String> responseHandler = new ResponseHandler<String>() {
        @Override
        public String handleResponse(org.apache.http.HttpResponse response) throws IOException {
          int status = response.getStatusLine().getStatusCode();
          if (status >= 200 && status < 300) {
            HttpEntity responseEntity = response.getEntity();
            return responseEntity != null ? EntityUtils.toString(responseEntity) : null;
          } else {
            throw new ClientProtocolException("Unexpected response status - token Useall: " + status);
          }
        }
      };
      CloseableHttpClient httpClientToken = HttpClients.createDefault();
      String responseBody = httpClientToken.execute(httpPost, responseHandler);
      RetornoLoginTokenDTO retornoToken = new ObjectMapper()
              .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)
              .readValue(responseBody, RetornoLoginTokenDTO.class);
      request.header("Authorization", "Bearer " + retornoToken.AccessToken);
      request.header("UseAuth-Empresa", String.valueOf(retornoToken.CodigoEmpresa));
      request.header("UseAuth-Filial", String.valueOf(retornoToken.CodigoFilial));
    }
    catch (Exception expToken) {
      throw LOG.unableToExecuteRequest(expToken);
    }

    HttpRequestBase httpRequest = createHttpRequest(request);

    HttpRequestInvocation invocation = new HttpRequestInvocation(httpRequest, request, requestInterceptors, httpClient);

    try {
      return createResponse((CloseableHttpResponse) invocation.proceed());
    } catch (Exception e) {
      throw LOG.unableToExecuteRequest(e);
    }

  }

  protected abstract R createResponse(CloseableHttpResponse response);

  @Override
  public abstract Q createRequest();

  /**
   * creates a apache Http* representation of the request.
   *
   * @param request the given request
   * @return {@link HttpRequestBase} an apache representation of the request
   */
  protected <T extends HttpRequestBase> T createHttpRequest(Q request) {
    T httpRequest = createHttpRequestBase(request);

    applyHeaders(httpRequest, request.getHeaders());

    applyPayload(httpRequest, request);

    return httpRequest;
  }

  @SuppressWarnings("unchecked")
  protected <T extends HttpRequestBase> T createHttpRequestBase(Q request) {
    String url = request.getUrl();
    if (url != null && !url.trim().isEmpty()) {
      String method = request.getMethod();
      if (HttpGet.METHOD_NAME.equals(method)) {
        return (T) new HttpGet(url);
      } else if (HttpPost.METHOD_NAME.equals(method)) {
        return (T) new HttpPost(url);
      } else if (HttpPut.METHOD_NAME.equals(method)) {
        return (T) new HttpPut(url);
      } else if (HttpDelete.METHOD_NAME.equals(method)) {
        return (T) new HttpDelete(url);
      } else if (HttpPatch.METHOD_NAME.equals(method)) {
        return (T) new HttpPatch(url);
      } else if (HttpHead.METHOD_NAME.equals(method)) {
        return (T) new HttpHead(url);
      } else if (HttpOptions.METHOD_NAME.equals(method)) {
        return (T) new HttpOptions(url);
      } else if (HttpTrace.METHOD_NAME.equals(method)) {
        return (T) new HttpTrace(url);
      } else {
        throw LOG.unknownHttpMethod(method);
      }
    }
    else {
      throw LOG.requestUrlRequired();
    }
  }

  protected <T extends HttpRequestBase> void applyHeaders(T httpRequest, Map<String, String> headers) {
    if (headers != null) {
      for (Map.Entry<String, String> entry : headers.entrySet()) {
        httpRequest.setHeader(entry.getKey(), entry.getValue());
        LOG.setHeader(entry.getKey(), entry.getValue());
      }
    }
  }

  protected <T extends HttpRequestBase> void applyPayload(T httpRequest, Q request) {
    if (httpMethodSupportsPayload(httpRequest)) {
      if (request.getPayload() != null) {
        byte[] bytes = request.getPayload().getBytes(charset);
        ByteArrayInputStream payload = new ByteArrayInputStream(bytes);
        InputStreamEntity entity = new InputStreamEntity(payload, bytes.length);
        ((HttpEntityEnclosingRequestBase) httpRequest).setEntity(entity);
      }
    }
    else if (request.getPayload() != null) {
      LOG.payloadIgnoredForHttpMethod(request.getMethod());
    }
  }

  protected <T extends HttpRequestBase> boolean httpMethodSupportsPayload(T httpRequest) {
    return httpRequest instanceof HttpEntityEnclosingRequestBase;
  }

}

class RetornoLoginTokenDTO
{
    @JsonProperty("access_token")
    public String AccessToken;

    @JsonProperty("CodigoUsuario")
    public int CodigoUsuario;

    @JsonProperty("CodigoEmpresa")
    public int CodigoEmpresa;

    @JsonProperty("CodigoFilial")
    public int CodigoFilial;
}