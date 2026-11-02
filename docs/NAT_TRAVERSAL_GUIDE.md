# NAT Traversal Testing and Configuration Guide

> **v0.13.0+ Note**: saorsa-transport uses a symmetric P2P architecture where all nodes have equal capabilities. There are no "client", "server", or "bootstrap" roles. Every node can connect to other nodes, accept connections, and coordinate NAT traversal for peers.

This guide provides detailed information on testing and configuring NAT traversal in saorsa-transport, including setup instructions for different NAT types and troubleshooting common issues.

## Table of Contents

1. [NAT Types Overview](#nat-types-overview)
2. [Local NAT Simulation](#local-nat-simulation)
3. [Configuration Options](#configuration-options)
4. [Testing Procedures](#testing-procedures)
5. [Troubleshooting](#troubleshooting)
6. [Performance Optimization](#performance-optimization)

## NAT Types Overview

saorsa-transport supports traversal through four primary NAT types:

### 1. Full Cone NAT (One-to-One NAT)
- **Characteristics**: Maps internal IP:port to external IP:port
- **Behavior**: Any external host can send packets to the internal host
- **Success Rate**: ~99%
- **Common In**: Basic home routers, some enterprise networks

### 2. Address Restricted Cone NAT
- **Characteristics**: External host must receive a packet first
- **Behavior**: Filters by source IP address only
- **Success Rate**: ~95%
- **Common In**: Most home routers

### 3. Port Restricted Cone NAT
- **Characteristics**: Filters by source IP:port combination
- **Behavior**: More restrictive than address restricted
- **Success Rate**: ~90%
- **Common In**: Security-conscious networks

### 4. Symmetric NAT
- **Characteristics**: Different mapping for each destination
- **Behavior**: Most restrictive, unpredictable port allocation
- **Success Rate**: ~85%
- **Common In**: Corporate firewalls, mobile carriers

### 5. Carrier-Grade NAT (CGNAT)
- **Characteristics**: Multiple layers of NAT
- **Behavior**: Extremely restrictive, limited port range
- **Success Rate**: ~70-80%
- **Common In**: Mobile networks, large ISPs

## Local NAT Simulation

### Using iptables (Linux)

#### Full Cone NAT
```bash
# Enable IP forwarding
sudo sysctl -w net.ipv4.ip_forward=1

# Setup Full Cone NAT
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
sudo iptables -A FORWARD -i eth1 -o eth0 -j ACCEPT
sudo iptables -A FORWARD -i eth0 -o eth1 -m state --state RELATED,ESTABLISHED -j ACCEPT
```

#### Symmetric NAT
```bash
# Setup Symmetric NAT with random port allocation
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE --random
sudo iptables -A FORWARD -i eth1 -o eth0 -j ACCEPT
sudo iptables -A FORWARD -i eth0 -o eth1 -m state --state RELATED,ESTABLISHED -j ACCEPT
```

#### Port Restricted NAT
```bash
# Setup Port Restricted NAT
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
sudo iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
sudo iptables -A FORWARD -i eth0 -o eth1 -j DROP
```

### Using Network Namespaces

Create isolated network environments for testing:

```bash
# Create network namespaces
sudo ip netns add client_ns
sudo ip netns add nat_ns
sudo ip netns add server_ns

# Create virtual ethernet pairs
sudo ip link add veth0 type veth peer name veth1
sudo ip link add veth2 type veth peer name veth3

# Connect namespaces
sudo ip link set veth1 netns client_ns
sudo ip link set veth0 netns nat_ns
sudo ip link set veth2 netns nat_ns
sudo ip link set veth3 netns server_ns

# Configure IP addresses
sudo ip netns exec client_ns ip addr add 192.168.1.2/24 dev veth1
sudo ip netns exec nat_ns ip addr add 192.168.1.1/24 dev veth0
sudo ip netns exec nat_ns ip addr add 10.0.0.1/24 dev veth2
sudo ip netns exec server_ns ip addr add 10.0.0.2/24 dev veth3

# Enable interfaces
sudo ip netns exec client_ns ip link set veth1 up
sudo ip netns exec nat_ns ip link set veth0 up
sudo ip netns exec nat_ns ip link set veth2 up
sudo ip netns exec server_ns ip link set veth3 up

# Configure NAT in nat_ns
sudo ip netns exec nat_ns iptables -t nat -A POSTROUTING -o veth2 -j MASQUERADE
sudo ip netns exec nat_ns sysctl -w net.ipv4.ip_forward=1
```

## Configuration Options

### Transport Parameters

Configure NAT traversal behavior in saorsa-transport:

```rust
// v0.13.0+: All nodes are symmetric - no role configuration needed
// Transport Parameters for NAT traversal:
// - 0x3d7e9f0bca12fea6: NAT traversal capability
// - 0x3d7e9f0bca12fea8: RFC-compliant frame format
// - 0x9f81a176: Address discovery

// Configure via P2pConfig
let config = P2pConfig::builder()
    .known_peer("peer.example.com:9000".parse()?)
    .nat(NatConfig {
        max_candidates: 10,
        enable_symmetric_nat: true,
        ..Default::default()
    })
    .build()?;
```

### Configuration File

Create `config.toml`:

```toml
[nat_traversal]
enabled = true
# v0.13.0+: No role field - all nodes are symmetric P2P nodes
max_candidates = 10
punch_timeout_ms = 5000
enable_address_prediction = true
prediction_range = 100

[discovery]
enable_local_discovery = true
enable_stun_like_discovery = true
# v0.13.0+: Uses known_peers instead of bootstrap_nodes
known_peers = [
    "quic.saorsalabs.com:9000",
    "backup.example.com:9000"
]

[protocols]
enable_add_address = true      # 0x3d7e90-91
enable_punch_me_now = true     # 0x3d7e92-93
enable_remove_address = true   # 0x3d7e94
enable_observed_address = true # 0x9f81a6-a7
```

## Testing Procedures

### Comprehensive NAT Test Suite

```bash
# Run all NAT traversal tests
cargo test --test nat_traversal_comprehensive -- --nocapture

# Run specific NAT scenario
cargo test --test nat_traversal_comprehensive test_symmetric_nat -- --nocapture

# Run with detailed logging
RUST_LOG=saorsa_transport::nat_traversal=trace cargo test nat_traversal
```

### Performance Testing

```bash
# Measure NAT traversal success rate
cargo bench --bench nat_traversal_performance

# Test under load
cargo test --test connection_lifecycle_tests stress -- --ignored

# Measure hole punching latency
cargo run --example nat_latency_test
```

## Troubleshooting

### Common Issues

#### 1. No Connection Established

**Symptoms**: Timeout errors, no successful connections

**Diagnosis**:
```bash
# Check if bootstrap is reachable
nc -zv bootstrap-host 9000

# Verify NAT type
curl https://ipinfo.io/ip  # External IP
ip addr show  # Internal IP

# Check firewall
sudo iptables -L -n | grep 9000
```

**Solutions**:
- Ensure initial peer (known_peer) has reachable IP
- Check firewall rules on both ends
- Verify network connectivity

#### 2. Low Success Rate

**Symptoms**: < 80% success rate for Full Cone NAT

**Diagnosis**:
```bash
# Enable detailed logging
RUST_LOG=saorsa_transport::nat_traversal=debug cargo test nat_traversal -- --nocapture > debug.log 2>&1

# Check candidate discovery
grep "Discovered candidate" debug.log

# Verify hole punching attempts
grep "PUNCH_ME_NOW" debug.log
```

**Solutions**:
- Increase `max_candidates` setting
- Extend `punch_timeout` duration
- Enable address prediction for symmetric NAT

#### 3. Symmetric NAT Failures

**Symptoms**: Consistent failures with symmetric NAT

**Diagnosis**:
```bash
# Test port allocation pattern
./scripts/test-symmetric-nat-pattern.sh

# Check prediction accuracy
grep "Predicted port" debug.log
```

**Solutions**:
```toml
[nat_traversal]
enable_address_prediction = true
prediction_range = 200  # Increase range
symmetric_nat_retry_count = 5
```

### Debug Tools

#### NAT Type Detection

```bash
# Run NAT type detection
cargo run --example detect_nat_type

# Output example:
# NAT Type: Symmetric
# External IP: 203.0.113.1
# Port allocation: Random
# Hairpinning: Not supported
```

#### Connection Diagnostics

```bash
# Run connection diagnostics
cargo run --example connection_diagnostics -- --target bootstrap:9000

# Provides:
# - RTT measurements
# - Packet loss rate
# - NAT traversal attempts
# - Success/failure reasons
```

#### Packet Capture

```bash
# Capture NAT traversal packets
sudo tcpdump -i any -w nat_traversal.pcap \
  'udp and (port 9000 or port 9001)'

# Analyze with Wireshark
wireshark nat_traversal.pcap
# Filter: quic.frame_type == 0x40  # ADD_ADDRESS frames
```

## Performance Optimization

### Optimize Candidate Discovery

```rust
// Configure aggressive candidate discovery
let mut config = NatTraversalConfig::default();
config.enable_local_discovery = true;
config.enable_upnp_igd = true;
config.prediction_algorithm = PredictionAlgorithm::Adaptive;
config.parallel_attempts = 5;
```

### Reduce Hole Punching Latency

```toml
[nat_traversal.timing]
initial_retry_interval_ms = 100  # Start fast
retry_multiplier = 1.5          # Exponential backoff
max_retry_interval_ms = 2000    # Cap retries
punch_burst_size = 3            # Send multiple packets
```

### Connection Pooling

```rust
// Reuse successful NAT mappings
let pool = ConnectionPool::new()
    .with_nat_cache_duration(Duration::from_secs(300))
    .with_max_cached_mappings(100);
```

## Best Practices

1. **Always test with realistic NAT**
   - Use Docker containers for consistency
   - Test all NAT types in CI/CD

2. **Monitor success rates**
   - Alert on < 90% for Full Cone
   - Alert on < 80% for Symmetric

3. **Optimize for mobile networks**
   - Expect CGNAT and symmetric NAT
   - Implement aggressive retry strategies

4. **Handle failures gracefully**
   - Implement relay fallback
   - Provide clear error messages

5. **Regular testing**
   ```bash
   # Add to CI pipeline
   ./scripts/nat-traversal-regression-test.sh
   ```

## Advanced Topics

### Custom NAT Traversal Strategies

Implement custom strategies for specific network environments:

```rust
pub trait NatTraversalStrategy {
    fn discover_candidates(&self) -> Vec<CandidateAddress>;
    fn predict_symmetric_port(&self, history: &[u16]) -> u16;
    fn should_retry(&self, attempt: u32, last_error: &Error) -> bool;
}

// Example: Aggressive strategy for mobile networks
struct MobileNetworkStrategy;

impl NatTraversalStrategy for MobileNetworkStrategy {
    fn discover_candidates(&self) -> Vec<CandidateAddress> {
        // Include cellular interface addresses
        // Predict multiple port ranges
        // Add TURN relay candidates
    }
    
    fn predict_symmetric_port(&self, history: &[u16]) -> u16 {
        // Use machine learning model trained on mobile NAT behavior
    }
    
    fn should_retry(&self, attempt: u32, last_error: &Error) -> bool {
        // More aggressive retries for mobile networks
        attempt < 10 && !matches!(last_error, Error::PermanentFailure)
    }
}
```

### Protocol Extensions

saorsa-transport implements QUIC NAT traversal extensions per draft-seemann-quic-nat-traversal-02:

- **Transport Parameter 0x58**: Negotiates NAT traversal support
- **ADD_ADDRESS (0x3d7e90-91)**: Advertise candidate addresses
- **PUNCH_ME_NOW (0x3d7e92-93)**: Coordinate hole punching
- **REMOVE_ADDRESS (0x3d7e94)**: Remove failed candidates
- **OBSERVED_ADDRESS (0x9f81a6-a7)**: Report observed addresses (per draft-ietf-quic-address-discovery-00)

### Integration with Other Protocols

```rust
// WebRTC-style ICE integration
let ice_agent = IceAgent::new()
    .with_quic_transport(quic_endpoint)
    .with_stun_servers(vec!["stun.l.google.com:19302"]);

// Custom protocol bridging
let bridge = ProtocolBridge::new()
    .add_protocol(QuicNatTraversal::new())
    .add_protocol(WebRtcDataChannel::new())
    .with_fallback(TurnRelay::new());
```

## Conclusion

Successful NAT traversal is critical for P2P connectivity. This guide provides:

- Comprehensive testing procedures for all NAT types
- Docker-based simulation environments
- Configuration options for different scenarios
- Troubleshooting steps for common issues
- Performance optimization techniques

Regular testing with these procedures ensures saorsa-transport maintains high connectivity success rates across diverse network environments.