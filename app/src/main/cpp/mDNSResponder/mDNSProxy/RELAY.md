# DNSSD Discovery Relay

## Implementation

## Requires

# Async library

All of the services in this implementatation are going to require some kind
of asynchronous network library.   The discovery relay will (I think) require the
following features:

* Register a socket for read/write/connection drop notification
* Buffered write to socket
* Request callback when any data available for read
* Request callback with n bytes of data when available
* Listen on port (TCP or UDP)
* Connect to port (TCP or UDP)
* Unbuffered send to port (UDP)
  
The Apple mDNSresponder code already has shims for various operating systems; for
now we are just using that code.   It may make sense at some point to replace this
with a less complex system, since the mDNSResponder code is quite large and one of
the goals of this project is to make something as lightweight as possible.


## To Do

These are the bits that are not done yet, and need to be done.   As they are done,
they should be documented under the **Implementation** heading, and the bits listed
below that are done should be marked (done) or (in progress) as appropriate.

* Configuration database
  * Information about this relay
    * Public key
    * Private key
    * IP address/port pairs to listen on
    * List of interfaces on which relay service is permitted
  * List of permitted Discovery proxies
    * Public key
    * IP source address/port pairs
    * List of interfaces this proxy may listen on (could be "all")
  * Parser for text config file
  * Hookup to HNCP

* TCP listener
  * Listen on a port (DONE)
  * Accept a connection (DONE)
  * Validate source as being from allowed discovery proxy
* TLS receiver
  * Start up connection
  * Request client validation
  * Validate that client credentials provided correspond to server that was
    identified by IP source when TCP accept() was evaluated.
* DSO Wrapper
  * Receive and dispatch DSO messages (DONE)
  * Wrap and transmit DSO messages
* mDNS relay
  * Receive mDNS messages
  * Transmit mDNS messages to connected Discovery Proxies that have subscribed
    to the link on which the message is received
  * Transmit messages from Discovery proxies on link (called by DSO dispatcher)
* Command Channel
  * Accepts configuration (e.g. when running HNCP)
  * Can query relay status
  * Can trigger reread of static conf file if present
