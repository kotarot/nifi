/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.nifi.controller.queue.clustered.server;

import org.apache.http.conn.ssl.DefaultHostnameVerifier;
import org.apache.nifi.cluster.coordination.ClusterCoordinator;
import org.apache.nifi.cluster.protocol.NodeIdentifier;
import org.apache.nifi.events.EventReporter;
import org.apache.nifi.reporting.Severity;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSession;
import java.util.List;
import java.util.stream.Collectors;

public class ClusterLoadBalanceAuthorizer implements LoadBalanceAuthorizer {
    private static final Logger logger = LoggerFactory.getLogger(ClusterLoadBalanceAuthorizer.class);

    private final ClusterCoordinator clusterCoordinator;
    private final EventReporter eventReporter;

    public ClusterLoadBalanceAuthorizer(final ClusterCoordinator clusterCoordinator, final EventReporter eventReporter) {
        this.clusterCoordinator = clusterCoordinator;
        this.eventReporter = eventReporter;
    }

    @Override
    public void authorize(final SSLSession sslSession) throws NotAuthorizedException {
        final List<String> nodeIds = clusterCoordinator.getNodeIdentifiers().stream()
                .map(NodeIdentifier::getApiAddress)
                .collect(Collectors.toList());

        for (final String nodeId : nodeIds) {
            final HostnameVerifier verifier = new DefaultHostnameVerifier();
            if (verifier.verify(nodeId, sslSession)) {
                logger.debug("Authorizing Client to Load Balance data");
                return;
            }
        }

        final String message = String.format("Authorization failed for Client ID's to Load Balance data because none of the ID's are known Cluster Node Identifiers");

        logger.warn(message);
        eventReporter.reportEvent(Severity.WARNING, "Load Balanced Connections", message);
        throw new NotAuthorizedException("Client ID's are not authorized to Load Balance data");
    }
}
