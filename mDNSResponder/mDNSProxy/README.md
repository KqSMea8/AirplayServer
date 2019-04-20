# dnssd-ref
DNS Service Discovery Reference Implementation

This is a reference implementation of DNS Service Discovery service.  The goal of this implementation is
to provide a fully functional collection of DNSSD services that can be used together or in combination with
other implementations of the various DNSSD technologies.
DNSSD is described in [RFC 6763](https://tools.ietf.org/html/rfc6763).

Host (client) implementations of DNSSD are widespread.   Service implementations of DNSSD using mDNS are also widespread.
However, high quality, highly automated
DNSSD implementations that can be queried using the DNS protocol (that is, not mDNS) are not.   The goal of this
project is to produce a complete reference implementation of each of the building blocks of a complete DNSSD solution that
can be queried over the DNS.

Information on the DNSSD Relay implementation is [here](RELAY.md).

This includes:

* [Discovery Proxy](https://tools.ietf.org/html/draft-ietf-dnssd-hybrid): finds
answers for DNSSD queries over DNS by proxying them to multicast DNS.
* [Discovery Relay](https://tools.ietf.org/html/draft-sctl-dnssd-mdns-relay): uses DNS
Stateful Operations to relay mDNS queries from and
mDNS responses to Discovery Proxies on other links
* [Discovery Broker](https://tools.ietf.org/html/draft-sctl-discovery-broker): aggregates
answers from one or more Discovery Proxies, possibly rewriting the answers
* [Service Registration](https://tools.ietf.org/html/draft-sctl-service-registration): allows
DNSSD services to publish the services they offer on a first come, first served
process using public key cryptography to protect names once claimed
