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

import org.apache.http.client.methods.CloseableHttpResponse;
import org.camunda.connect.usehttpclient.HttpConnector;
import org.camunda.connect.usehttpclient.HttpRequest;
import org.camunda.connect.usehttpclient.HttpResponse;

public class HttpConnectorImpl extends AbstractHttpConnector<HttpRequest, HttpResponse> implements HttpConnector {

  public HttpConnectorImpl() {
    super(HttpConnector.ID);
  }

  public HttpConnectorImpl(String connectorId) {
    super(connectorId);
  }

  public HttpRequest createRequest() {
    return new HttpRequestImpl(this);
  }

  protected HttpResponse createResponse(CloseableHttpResponse response) {
    return new HttpResponseImpl(response);
  }

}
