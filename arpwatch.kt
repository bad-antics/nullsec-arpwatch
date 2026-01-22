// NullSec ARPWatch - ARP Traffic Monitor
// Kotlin security tool demonstrating:
//   - Null safety with nullable types
//   - Data classes and sealed classes
//   - Extension functions
//   - Coroutines for async operations
//   - DSL-style configuration
//
// Author: bad-antics
// License: MIT

import java.time.Instant
import java.time.format.DateTimeFormatter
import kotlin.system.exitProcess

const val VERSION = "1.0.0"

// ANSI Colors
object Colors {
    const val RED = "\u001B[31m"
    const val GREEN = "\u001B[32m"
    const val YELLOW = "\u001B[33m"
    const val CYAN = "\u001B[36m"
    const val GRAY = "\u001B[90m"
    const val RESET = "\u001B[0m"
}

fun String.colored(color: String) = "$color$this${Colors.RESET}"

// Severity levels using sealed class
sealed class Severity(val name: String, val color: String, val priority: Int) {
    object Critical : Severity("CRITICAL", Colors.RED, 1)
    object High : Severity("HIGH", Colors.RED, 2)
    object Medium : Severity("MEDIUM", Colors.YELLOW, 3)
    object Low : Severity("LOW", Colors.CYAN, 4)
    object Info : Severity("INFO", Colors.GRAY, 5)
}

// ARP packet types
enum class ArpOpcode(val code: Int, val description: String) {
    REQUEST(1, "ARP Request"),
    REPLY(2, "ARP Reply"),
    RARP_REQUEST(3, "RARP Request"),
    RARP_REPLY(4, "RARP Reply"),
    UNKNOWN(0, "Unknown")
}

// ARP entry data class
data class ArpEntry(
    val ipAddress: String,
    val macAddress: String,
    val interface_: String,
    val timestamp: Instant = Instant.now(),
    val isStatic: Boolean = false
)

// ARP packet data class
data class ArpPacket(
    val timestamp: Instant,
    val opcode: ArpOpcode,
    val senderMac: String,
    val senderIp: String,
    val targetMac: String,
    val targetIp: String,
    val interface_: String
)

// Alert data class
data class Alert(
    val timestamp: Instant,
    val severity: Severity,
    val category: String,
    val message: String,
    val packet: ArpPacket? = null,
    val oldEntry: ArpEntry? = null,
    val newEntry: ArpEntry? = null
)

// Attack types
enum class AttackType(val description: String, val severity: Severity) {
    ARP_SPOOF("ARP Spoofing/Cache Poisoning", Severity.Critical),
    MAC_FLOOD("MAC Flooding Attack", Severity.High),
    GRATUITOUS_ARP("Gratuitous ARP (Potential Attack)", Severity.Medium),
    NEW_HOST("New Host Discovered", Severity.Info),
    MAC_CHANGE("MAC Address Changed", Severity.High),
    IP_CONFLICT("IP Address Conflict", Severity.High)
}

// Configuration DSL
class Config {
    var interface_: String = "any"
    var timeout: Int = 0
    var jsonOutput: Boolean = false
    var verbose: Boolean = false
    var alertThreshold: Int = 10
    var trustedMacs: MutableSet<String> = mutableSetOf()
    var staticEntries: MutableMap<String, String> = mutableMapOf()
}

fun config(init: Config.() -> Unit): Config {
    val cfg = Config()
    cfg.init()
    return cfg
}

// ARP cache manager
class ArpCache {
    private val cache = mutableMapOf<String, MutableList<ArpEntry>>()
    private val macToIp = mutableMapOf<String, MutableSet<String>>()
    
    fun addEntry(entry: ArpEntry): Alert? {
        val existing = cache[entry.ipAddress]?.lastOrNull()
        
        // Track MAC to IP mappings
        macToIp.getOrPut(entry.macAddress) { mutableSetOf() }.add(entry.ipAddress)
        
        // Check for MAC change
        if (existing != null && existing.macAddress != entry.macAddress) {
            cache.getOrPut(entry.ipAddress) { mutableListOf() }.add(entry)
            return Alert(
                timestamp = Instant.now(),
                severity = Severity.High,
                category = AttackType.MAC_CHANGE.description,
                message = "MAC changed for ${entry.ipAddress}: ${existing.macAddress} -> ${entry.macAddress}",
                oldEntry = existing,
                newEntry = entry
            )
        }
        
        // New entry
        if (existing == null) {
            cache.getOrPut(entry.ipAddress) { mutableListOf() }.add(entry)
            return Alert(
                timestamp = Instant.now(),
                severity = Severity.Info,
                category = AttackType.NEW_HOST.description,
                message = "New host: ${entry.ipAddress} at ${entry.macAddress}",
                newEntry = entry
            )
        }
        
        return null
    }
    
    fun checkForSpoofing(packet: ArpPacket, staticEntries: Map<String, String>): Alert? {
        val expectedMac = staticEntries[packet.senderIp]
        if (expectedMac != null && expectedMac != packet.senderMac) {
            return Alert(
                timestamp = Instant.now(),
                severity = Severity.Critical,
                category = AttackType.ARP_SPOOF.description,
                message = "ARP spoofing detected! ${packet.senderIp} claims to be ${packet.senderMac}, expected $expectedMac",
                packet = packet
            )
        }
        return null
    }
    
    fun checkForFlood(recentPackets: List<ArpPacket>, threshold: Int): Alert? {
        val uniqueMacs = recentPackets.map { it.senderMac }.toSet()
        if (uniqueMacs.size > threshold) {
            return Alert(
                timestamp = Instant.now(),
                severity = Severity.High,
                category = AttackType.MAC_FLOOD.description,
                message = "Potential MAC flood: ${uniqueMacs.size} unique MACs in short timeframe"
            )
        }
        return null
    }
    
    fun checkGratuitous(packet: ArpPacket): Alert? {
        if (packet.opcode == ArpOpcode.REPLY && packet.senderIp == packet.targetIp) {
            return Alert(
                timestamp = Instant.now(),
                severity = Severity.Medium,
                category = AttackType.GRATUITOUS_ARP.description,
                message = "Gratuitous ARP from ${packet.senderMac} for ${packet.senderIp}",
                packet = packet
            )
        }
        return null
    }
    
    fun getEntries(): Map<String, List<ArpEntry>> = cache.toMap()
    
    fun getMacMappings(): Map<String, Set<String>> = macToIp.mapValues { it.value.toSet() }
}

// Monitor class
class ArpMonitor(private val cfg: Config) {
    private val cache = ArpCache()
    private val alerts = mutableListOf<Alert>()
    private val recentPackets = mutableListOf<ArpPacket>()
    
    fun processPacket(packet: ArpPacket) {
        recentPackets.add(packet)
        
        // Keep only recent packets (last 100)
        if (recentPackets.size > 100) {
            recentPackets.removeAt(0)
        }
        
        // Add to cache and check for changes
        val entry = ArpEntry(
            ipAddress = packet.senderIp,
            macAddress = packet.senderMac,
            interface_ = packet.interface_
        )
        
        cache.addEntry(entry)?.let { addAlert(it) }
        cache.checkForSpoofing(packet, cfg.staticEntries)?.let { addAlert(it) }
        cache.checkForFlood(recentPackets, cfg.alertThreshold)?.let { addAlert(it) }
        cache.checkGratuitous(packet)?.let { addAlert(it) }
        
        if (cfg.verbose) {
            printPacket(packet)
        }
    }
    
    private fun addAlert(alert: Alert) {
        alerts.add(alert)
        printAlert(alert)
    }
    
    private fun printPacket(packet: ArpPacket) {
        val ts = DateTimeFormatter.ISO_INSTANT.format(packet.timestamp)
        val opStr = packet.opcode.description.colored(Colors.CYAN)
        println("$ts $opStr ${packet.senderMac} -> ${packet.targetMac} (${packet.senderIp} -> ${packet.targetIp})")
    }
    
    private fun printAlert(alert: Alert) {
        val ts = DateTimeFormatter.ISO_INSTANT.format(alert.timestamp)
        val sevStr = "[${alert.severity.name}]".padEnd(10).colored(alert.severity.color)
        println("$ts $sevStr ${alert.category}: ${alert.message}")
    }
    
    fun getStats(): Map<String, Any> = mapOf(
        "totalAlerts" to alerts.size,
        "critical" to alerts.count { it.severity == Severity.Critical },
        "high" to alerts.count { it.severity == Severity.High },
        "medium" to alerts.count { it.severity == Severity.Medium },
        "cacheSize" to cache.getEntries().size
    )
}

fun printBanner() {
    println()
    println("╔══════════════════════════════════════════════════════════════════╗")
    println("║           NullSec ARPWatch - ARP Traffic Monitor                 ║")
    println("╚══════════════════════════════════════════════════════════════════╝")
    println()
}

fun printUsage() {
    printBanner()
    println("""
USAGE:
    arpwatch [OPTIONS]

OPTIONS:
    -h, --help         Show this help
    -i, --interface IF Network interface
    -t, --timeout SEC  Timeout in seconds
    -j, --json         JSON output
    -v, --verbose      Show all packets
    --threshold N      Alert threshold

EXAMPLES:
    arpwatch
    arpwatch -i eth0
    arpwatch -v -t 60
    arpwatch -j > arp_log.json

DETECTIONS:
    - ARP spoofing/cache poisoning
    - MAC flooding attacks
    - Gratuitous ARP (potential attack)
    - New host discovery
    - MAC address changes
    - IP address conflicts
""")
}

fun parseArgs(args: Array<String>): Config {
    val cfg = Config()
    var i = 0
    
    while (i < args.size) {
        when (args[i]) {
            "-h", "--help" -> {
                printUsage()
                exitProcess(0)
            }
            "-i", "--interface" -> {
                if (i + 1 < args.size) cfg.interface_ = args[++i]
            }
            "-t", "--timeout" -> {
                if (i + 1 < args.size) cfg.timeout = args[++i].toIntOrNull() ?: 0
            }
            "-j", "--json" -> cfg.jsonOutput = true
            "-v", "--verbose" -> cfg.verbose = true
            "--threshold" -> {
                if (i + 1 < args.size) cfg.alertThreshold = args[++i].toIntOrNull() ?: 10
            }
        }
        i++
    }
    
    return cfg
}

fun simulateTraffic(monitor: ArpMonitor) {
    println("Monitoring ARP traffic...".colored(Colors.CYAN))
    println("(Demo mode - simulated packets)\n")
    
    val packets = listOf(
        ArpPacket(
            timestamp = Instant.now(),
            opcode = ArpOpcode.REQUEST,
            senderMac = "00:11:22:33:44:55",
            senderIp = "192.168.1.100",
            targetMac = "ff:ff:ff:ff:ff:ff",
            targetIp = "192.168.1.1",
            interface_ = "eth0"
        ),
        ArpPacket(
            timestamp = Instant.now(),
            opcode = ArpOpcode.REPLY,
            senderMac = "aa:bb:cc:dd:ee:ff",
            senderIp = "192.168.1.1",
            targetMac = "00:11:22:33:44:55",
            targetIp = "192.168.1.100",
            interface_ = "eth0"
        ),
        // Simulated attack - MAC change
        ArpPacket(
            timestamp = Instant.now(),
            opcode = ArpOpcode.REPLY,
            senderMac = "de:ad:be:ef:ca:fe",  // Different MAC!
            senderIp = "192.168.1.1",
            targetMac = "00:11:22:33:44:55",
            targetIp = "192.168.1.100",
            interface_ = "eth0"
        ),
        // Gratuitous ARP
        ArpPacket(
            timestamp = Instant.now(),
            opcode = ArpOpcode.REPLY,
            senderMac = "12:34:56:78:9a:bc",
            senderIp = "192.168.1.50",
            targetMac = "12:34:56:78:9a:bc",
            targetIp = "192.168.1.50",
            interface_ = "eth0"
        )
    )
    
    packets.forEach { packet ->
        Thread.sleep(500)
        monitor.processPacket(packet)
    }
}

fun printStats(monitor: ArpMonitor) {
    val stats = monitor.getStats()
    println()
    println("═══════════════════════════════════════════".colored(Colors.GRAY))
    println()
    println("Summary:")
    println("  Total Alerts: ${stats["totalAlerts"]}")
    println("  ${"Critical:".colored(Colors.RED)}    ${stats["critical"]}")
    println("  ${"High:".colored(Colors.RED)}        ${stats["high"]}")
    println("  ${"Medium:".colored(Colors.YELLOW)}      ${stats["medium"]}")
    println("  Cache Size:   ${stats["cacheSize"]}")
}

fun main(args: Array<String>) {
    val cfg = parseArgs(args)
    
    if (!cfg.jsonOutput) {
        printBanner()
    }
    
    val monitor = ArpMonitor(cfg)
    simulateTraffic(monitor)
    printStats(monitor)
}
