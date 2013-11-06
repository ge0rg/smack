/**
 *
 * Copyright 2003-2007 Jive Software.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
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

package org.jivesoftware.smackx.iqversion.packet;

import java.util.Collections;
import java.util.Map;
import java.util.WeakHashMap;

import org.jivesoftware.smack.Connection;
import org.jivesoftware.smack.PacketListener;
import org.jivesoftware.smack.filter.PacketTypeFilter;
import org.jivesoftware.smack.packet.IQ;
import org.jivesoftware.smack.packet.Packet;
import org.jivesoftware.smack.provider.IQProvider;
import org.jivesoftware.smackx.ServiceDiscoveryManager;
import org.xmlpull.v1.XmlPullParser;

/**
 * A Version IQ packet, which is used by XMPP clients to discover version information
 * about the software running at another entity's JID.<p>
 *
 * An example to discover the version of the server:
 * <pre>
 * // Request the version from the server.
 * Version versionRequest = new Version();
 * timeRequest.setType(IQ.Type.GET);
 * timeRequest.setTo("example.com");
 *
 * // Create a packet collector to listen for a response.
 * PacketCollector collector = con.createPacketCollector(
 *                new PacketIDFilter(versionRequest.getPacketID()));
 *
 * con.sendPacket(versionRequest);
 *
 * // Wait up to 5 seconds for a result.
 * IQ result = (IQ)collector.nextResult(5000);
 * if (result != null && result.getType() == IQ.Type.RESULT) {
 *     Version versionResult = (Version)result;
 *     // Do something with result...
 * }</pre><p>
 *
 * @author Gaston Dombiak
 */
public class Version extends IQ {
    public static final String NAMESPACE = "jabber:iq:version";
    public static final String ELEMENT = "ping";

    private String name;
    private String version;
    private String os;

    /**
     * Creates a new Version object with given details.
     *
     * @param name The natural-language name of the software. This element is REQUIRED.
     * @param version The specific version of the software. This element is REQUIRED.
     * @param os The operating system of the queried entity. This element is OPTIONAL.
     */
    public Version(String name, String version, String os) {
        this.setType(IQ.Type.RESULT);
        this.name = name;
        this.version = version;
        this.os = os;
    }

    private Version(Version original) {
        this(original.name, original.version, original.os);
    }

    private Version() {
        super();
    }

    /**
     * Returns the natural-language name of the software. This property will always be
     * present in a result.
     *
     * @return the natural-language name of the software.
     */
    public String getName() {
        return name;
    }

    /**
     * Sets the natural-language name of the software. This message should only be
     * invoked when parsing the XML and setting the property to a Version instance.
     *
     * @param name the natural-language name of the software.
     */
    public void setName(String name) {
        this.name = name;
    }

    /**
     * Returns the specific version of the software. This property will always be
     * present in a result.
     *
     * @return the specific version of the software.
     */
    public String getVersion() {
        return version;
    }

    /**
     * Sets the specific version of the software. This message should only be
     * invoked when parsing the XML and setting the property to a Version instance.
     *
     * @param version the specific version of the software.
     */
    public void setVersion(String version) {
        this.version = version;
    }

    /**
     * Returns the operating system of the queried entity. This property will always be
     * present in a result.
     *
     * @return the operating system of the queried entity.
     */
    public String getOs() {
        return os;
    }

    /**
     * Sets the operating system of the queried entity. This message should only be
     * invoked when parsing the XML and setting the property to a Version instance.
     *
     * @param os operating system of the queried entity.
     */
    public void setOs(String os) {
        this.os = os;
    }

    public String getChildElementXML() {
        StringBuilder buf = new StringBuilder();
        buf.append("<query xmlns=\"jabber:iq:version\">");
        if (name != null) {
            buf.append("<name>").append(name).append("</name>");
        }
        if (version != null) {
            buf.append("<version>").append(version).append("</version>");
        }
        if (os != null) {
            buf.append("<os>").append(os).append("</os>");
        }
        buf.append("</query>");
        return buf.toString();
    }

    public static class Provider implements IQProvider {
        public IQ parseIQ(XmlPullParser parser) throws Exception {
            Version v = new Version();

            boolean done = false;
            while (!done) {
                int eventType = parser.next();
                if (eventType == XmlPullParser.START_TAG && parser.getName().equals("name")) {
                    v.setName(parser.nextText());
                }
                else if (eventType == XmlPullParser.START_TAG && parser.getName().equals("version")) {
                    v.setVersion(parser.nextText());
                }
                else if (eventType == XmlPullParser.START_TAG && parser.getName().equals("os")) {
                    v.setOs(parser.nextText());
                }
                else if (eventType == XmlPullParser.END_TAG && parser.getName().equals("query")) {
                    done = true;
                }
            }
            return v;
        }
    }

    public static class Manager {
        private static final Map<Connection, Manager> instances =
                Collections.synchronizedMap(new WeakHashMap<Connection, Manager>());

        private Version own_version;
        private Connection connection;

        // IQ Flood protection
        private long iqMinDelta = 100;
        private long lastIqStamp = 0; // timestamp of the last received IQ

        private Manager(final Connection connection) {
            this.connection = connection;
            instances.put(connection, this);

            ServiceDiscoveryManager sdm = ServiceDiscoveryManager.getInstanceFor(connection);
            sdm.addFeature(Version.NAMESPACE);

            connection.addPacketListener(new PacketListener() {
                /**
                 * Sends a Version reply on request
                 */
                public void processPacket(Packet packet) {
                    if (own_version == null)
                        return;
                    if (iqMinDelta > 0) {
                        // Ping flood protection enabled
                        long currentMillies = System.currentTimeMillis();
                        long delta = currentMillies - lastIqStamp;
                        lastIqStamp = currentMillies;
                        if (delta < iqMinDelta) {
                            return;
                        }
                    }
                    Version reply = new Version(own_version);
                    reply.setPacketID(packet.getPacketID());
                    reply.setFrom(packet.getTo());
                    reply.setTo(packet.getFrom());
                    connection.sendPacket(reply);
                }
            }
            , new PacketTypeFilter(Version.class));
        }

        public static synchronized Manager getInstanceFor(Connection connection) {
            Manager manager = instances.get(connection);

            if (manager == null) {
                manager = new Manager(connection);
            }

            return manager;
        }

        public void setVersion(Version v) {
            own_version = v;
        }
    }
}
