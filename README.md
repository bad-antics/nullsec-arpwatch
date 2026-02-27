# NullSec ARPWatch

Kotlin ARP traffic monitor demonstrating null safety, coroutines, and DSL-style configuration.

## Features

- **Null Safety** - Nullable types and safe calls
- **Data Classes** - Immutable packet/alert structures
- **Sealed Classes** - Type-safe severity levels
- **Extension Functions** - Clean API extensions
- **DSL Configuration** - Kotlin-style config blocks

## Detections

| Attack | Severity | Description |
|--------|----------|-------------|
| ARP Spoofing | Critical | Cache poisoning attacks |
| MAC Flooding | High | CAM table overflow |
| MAC Change | High | Unexpected MAC changes |
| IP Conflict | High | Duplicate IP addresses |
| Gratuitous ARP | Medium | Potential attack vector |
| New Host | Info | Host discovery |

## Build

```bash
# With kotlinc
kotlinc arpwatch.kt -include-runtime -d arpwatch.jar
java -jar arpwatch.jar

# With Gradle
gradle build
gradle run

# Native with GraalVM
native-image -jar arpwatch.jar
```

## Usage

```bash
# Basic monitoring
java -jar arpwatch.jar

# Specific interface
java -jar arpwatch.jar -i eth0

# Verbose mode
java -jar arpwatch.jar -v

# JSON output
java -jar arpwatch.jar -j > arp_log.json

# Custom threshold
java -jar arpwatch.jar --threshold 20
```

## Output Example

```
[CRITICAL] ARP Spoofing: MAC changed for 192.168.1.1
[HIGH]     MAC Flood: 50 unique MACs in short timeframe
[MEDIUM]   Gratuitous ARP from aa:bb:cc:dd:ee:ff
[INFO]     New Host: 192.168.1.100 at 00:11:22:33:44:55
```

## Author

bad-antics | [Twitter](https://x.com/AnonAntics)

## License

MIT
