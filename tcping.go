// tcping.go 使用TCP协议探测目标
package main

import (
	"bufio"
	"context"
	"flag"
	"math/rand"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/google/go-github/v45/github"
)

var version = "" // 在编译时设置

const (
	owner      = "pouriyajamshidi"
	repo       = "tcping"
	dnsTimeout = 2 * time.Second
)

// printer 是打印机需要实现的一组方法。
//
// 打印机不应该修改任何现有数据，也不应该进行任何计算。
// 它们应该只对给定的数据执行可视化操作。
type printer interface {
	// printStart 应该在程序启动后打印第一条消息。
	// 此消息只在最开始打印一次。
	printStart(hostname string, port uint16)

	// printProbeSuccess 应该在每次成功探测后打印消息。
	// hostname 可能为空，表示正在ping一个地址。
	// streak 是连续成功探测的次数。
	printProbeSuccess(sourceAddr string, userInput userInput, streak uint, rtt float32)

	// printProbeFail 应该在每次失败探测后打印消息。
	// hostname 可能为空，表示正在ping一个地址。
	// streak 是连续失败探测的次数。
	printProbeFail(userInput userInput, streak uint)

	// printRetryingToResolve 应该打印一条消息，包含它正在尝试解析IP的主机名。
	//
	// 这仅在应用 -r 标志时打印。
	printRetryingToResolve(hostname string)

	// printTotalDownTime 应该打印一个停机时间。
	//
	// 当主机不可用一段时间但最新探测成功（变得可用）时调用此函数。
	printTotalDownTime(downtime time.Duration)

	// printStatistics 应该打印一条包含有用统计信息的消息。
	//
	// 这在退出和用户按"Enter"键时调用。
	printStatistics(s tcping)

	// printVersion 应该打印当前版本。
	printVersion()

	// printInfo 应该打印一条消息，该消息与ping操作不直接相关，而是作为有用信息。
	//
	// 例如：使用 -u 标志时的新版本信息。
	printInfo(format string, args ...any)

	// printError 应该打印错误消息。
	// 打印机还应该在需要时在给定字符串后应用\n。
	printError(format string, args ...any)
}

type tcping struct {
	printer                   // printer holds the chosen printer implementation for outputting information and data.
	startTime                 time.Time
	endTime                   time.Time
	startOfUptime             time.Time
	startOfDowntime           time.Time
	lastSuccessfulProbe       time.Time
	lastUnsuccessfulProbe     time.Time
	ticker                    *time.Ticker // ticker is used to handle time between probes.
	longestUptime             longestTime
	longestDowntime           longestTime
	rtt                       []float32
	hostnameChanges           []hostnameChange
	userInput                 userInput
	ongoingSuccessfulProbes   uint
	ongoingUnsuccessfulProbes uint
	totalDowntime             time.Duration
	totalUptime               time.Duration
	totalSuccessfulProbes     uint
	totalUnsuccessfulProbes   uint
	retriedHostnameLookups    uint
	rttResults                rttResult
	destWasDown               bool // destWasDown is used to determine the duration of a downtime
	destIsIP                  bool // destIsIP suppresses printing the IP information twice when hostname is not provided
}

type userInput struct {
	ip                       netip.Addr
	hostname                 string
	networkInterface         networkInterface
	retryHostnameLookupAfter uint // Retry resolving target's hostname after a certain number of failed requests
	probesBeforeQuit         uint
	timeout                  time.Duration
	intervalBetweenProbes    time.Duration
	port                     uint16
	useIPv4                  bool
	useIPv6                  bool
	shouldRetryResolve       bool
	showFailuresOnly         bool
	showSourceAddress        bool
}

type genericUserInputArgs struct {
	retryResolve         *uint
	probesBeforeQuit     *uint
	timeout              *float64
	secondsBetweenProbes *float64
	intName              *string
	showFailuresOnly     *bool
	showSourceAddress    *bool
	args                 []string
}

type networkInterface struct {
	remoteAddr *net.TCPAddr
	dialer     net.Dialer
	use        bool
}

type longestTime struct {
	start    time.Time
	end      time.Time
	duration time.Duration
}

type rttResult struct {
	min        float32
	max        float32
	average    float32
	hasResults bool
}

type hostnameChange struct {
	Addr netip.Addr `json:"addr,omitempty"`
	When time.Time  `json:"when,omitempty"`
}

// signalHandler catches SIGINT and SIGTERM then prints tcping stats
func signalHandler(tcping *tcping) {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		shutdown(tcping)
	}()
}

// monitorSTDIN checks stdin to see whether the 'Enter' key was pressed
func monitorSTDIN(stdinChan chan bool) {
	reader := bufio.NewReader(os.Stdin)
	for {
		input, _ := reader.ReadString('\n')

		if input == "\n" || input == "\r" || input == "\r\n" {
			stdinChan <- true
		}
	}
}

// printStats is a helper method for printStatistics
// for the current printer.
//
// This should be used instead, as it makes
// all the necessary calculations beforehand.
func (t *tcping) printStats() {
	if t.destWasDown {
		calcLongestDowntime(t, time.Since(t.startOfDowntime))
	} else {
		calcLongestUptime(t, time.Since(t.startOfUptime))
	}
	t.rttResults = calcMinAvgMaxRttTime(t.rtt)

	t.printStatistics(*t)
}

// shutdown calculates endTime, prints statistics and calls os.Exit(0).
// This should be used as the main exit-point.
func shutdown(tcping *tcping) {
	tcping.endTime = time.Now()
	tcping.printStats()

	// if the printer type is `database`, close it before exiting
	if db, ok := tcping.printer.(*database); ok {
		db.conn.Close()
	}

	// if the printer type is `csvPrinter`, call the cleanup function before exiting
	if cp, ok := tcping.printer.(*csvPrinter); ok {
		cp.cleanup()
	}

	os.Exit(0)
}

// usage prints how tcping should be run
func usage() {
	executableName := os.Args[0]

	colorLightCyan("\nTCPING 版本 %s\n\n", version)
	colorRed("%s命令格式 :\n", executableName)
	colorRed("%s <主机名/ip> <端口号>  例如:\n", executableName)
	colorRed("%s www.example.com 443\n", executableName)
	colorYellow("\n[可选项]\n")

	flag.VisitAll(func(f *flag.Flag) {
		flagName := f.Name
		if len(f.Name) > 1 {
			flagName = "-" + flagName
		}

		colorYellow("  -%s : %s\n", flagName, f.Usage)
	})

	os.Exit(1)
}

// setPrinter selects the printer
func setPrinter(tcping *tcping, outputJSON, prettyJSON *bool, noColor *bool, timeStamp *bool, sourceAddress *bool, outputDb *string, outputCSV *string, args []string) {
	if *prettyJSON && !*outputJSON {
		colorRed("--pretty 标志在没有 -j 标志的情况下无效。")
		usage()
	}

	if *outputJSON {
		tcping.printer = newJSONPrinter(*prettyJSON)
	} else if *outputDb != "" {
		tcping.printer = newDB(*outputDb, args)
	} else if *outputCSV != "" {
		var err error
		tcping.printer, err = newCSVPrinter(*outputCSV, timeStamp, sourceAddress)
		if err != nil {
			tcping.printError("创建CSV文件失败: %s", err)
			os.Exit(1)
		}
	} else if *noColor {
		tcping.printer = newPlainPrinter(timeStamp)
	} else {
		tcping.printer = newColorPrinter(timeStamp)
	}
}

// showVersion displays the version and exits
func showVersion(tcping *tcping) {
	tcping.printVersion()
	os.Exit(0)
}

// setIPFlags ensures that either IPv4 or IPv6 is specified by the user and not both and sets it
func setIPFlags(tcping *tcping, ip4, ip6 *bool) {
	if *ip4 && *ip6 {
		tcping.printError("只能指定一个IP版本")
		usage()
	}
	if *ip4 {
		tcping.userInput.useIPv4 = true
	}
	if *ip6 {
		tcping.userInput.useIPv6 = true
	}
}

// setPort validates and sets the TCP/UDP port range
func setPort(tcping *tcping, args []string) {
	port, err := strconv.ParseUint(args[1], 10, 16)
	if err != nil {
		tcping.printError("无效的端口号: %s", args[1])
		os.Exit(1)
	}

	if port < 1 || port > 65535 {
		tcping.printError("端口应该在 1-65535 范围内")
		os.Exit(1)
	}
	tcping.userInput.port = uint16(port)
}

// setGenericArgs assigns the generic flags after sanity checks
func setGenericArgs(tcping *tcping, genericArgs genericUserInputArgs) {
	if *genericArgs.retryResolve > 0 {
		tcping.userInput.retryHostnameLookupAfter = *genericArgs.retryResolve
	}

	tcping.userInput.hostname = genericArgs.args[0]
	tcping.userInput.ip = resolveHostname(tcping)
	tcping.startTime = time.Now()
	tcping.userInput.probesBeforeQuit = *genericArgs.probesBeforeQuit
	tcping.userInput.timeout = secondsToDuration(*genericArgs.timeout)

	tcping.userInput.intervalBetweenProbes = secondsToDuration(*genericArgs.secondsBetweenProbes)
	if tcping.userInput.intervalBetweenProbes < 2*time.Millisecond {
		tcping.printError("等待间隔应大于 2 毫秒")
		os.Exit(1)
	}

	// 这作为跟踪IP更改的默认起始值。
	tcping.hostnameChanges = []hostnameChange{
		{tcping.userInput.ip, time.Now()},
	}

	if tcping.userInput.hostname == tcping.userInput.ip.String() {
		tcping.destIsIP = true
	}

	if tcping.userInput.retryHostnameLookupAfter > 0 && !tcping.destIsIP {
		tcping.userInput.shouldRetryResolve = true
	}

	if *genericArgs.intName != "" {
		tcping.userInput.networkInterface = newNetworkInterface(tcping, *genericArgs.intName)
	}

	tcping.userInput.showFailuresOnly = *genericArgs.showFailuresOnly

	tcping.userInput.showSourceAddress = *genericArgs.showSourceAddress
}

// processUserInput 获取并验证用户输入
func processUserInput(tcping *tcping) {
	useIPv4 := flag.Bool("4", false, "仅使用IPv4。")
	useIPv6 := flag.Bool("6", false, "仅使用IPv6。")
	retryHostnameResolveAfter := flag.Uint("r", 0, "在 <n> 次探测失败后重试解析目标主机名。例如：-r 10 表示10次失败后重试。")
	probesBeforeQuit := flag.Uint("c", 0, "在 <n> 次探测后停止，无论结果如何。默认无限制。")
	outputJSON := flag.Bool("j", false, "以JSON格式输出。")
	prettyJSON := flag.Bool("pretty", false, "在使用json输出格式时使用缩进。没有'-j'标志时无效。")
	noColor := flag.Bool("no-color", false, "不使用彩色输出。")
	showTimestamp := flag.Bool("D", false, "在输出中显示时间戳。")
	saveToCSV := flag.String("csv", "", "保存tcping输出到CSV文件的路径和文件名...如果用户请求统计信息，它将被保存到同名但附加了_stats的文件中。")
	showVer := flag.Bool("v", false, "显示版本。")
	checkUpdates := flag.Bool("u", false, "检查更新并退出。")
	secondsBetweenProbes := flag.Float64("i", 1, "发送探测之间的间隔。允许使用小数点分隔的实数。默认为一秒")
	timeout := flag.Float64("t", 1, "等待响应的时间，以秒为单位。允许使用实数。0表示无限超时。")
	outputDB := flag.String("db", "", "保存tcping输出到sqlite数据库的路径和文件名。")
	interfaceName := flag.String("I", "", "接口名称或地址。")
	showSourceAddress := flag.Bool("show-source-address", false, "显示用于探测的源地址和端口。")
	showFailuresOnly := flag.Bool("show-failures-only", false, "仅显示失败的探测。")
	showHelp := flag.Bool("h", false, "显示帮助信息。")

	flag.CommandLine.Usage = usage

	permuteArgs(os.Args[1:])
	flag.Parse()

	// validation for flag and args
	args := flag.Args()

	// we need to set printers first, because they're used for
	// error reporting and other output.
	setPrinter(tcping, outputJSON, prettyJSON, noColor, showTimestamp, showSourceAddress, outputDB, saveToCSV, args)

	// Handle -v flag
	if *showVer {
		showVersion(tcping)
	}

	// Handle -h flag
	if *showHelp {
		usage()
	}

	// Handle -u flag
	if *checkUpdates {
		checkForUpdates(tcping)
	}

	// host and port must be specified
	if len(args) != 2 {
		usage()
	}

	// Check whether both the ipv4 and ipv6 flags are attempted set if ony one, error otherwise.
	setIPFlags(tcping, useIPv4, useIPv6)

	// Check if the port is valid and set it.
	setPort(tcping, args)

	// set generic args
	genericArgs := genericUserInputArgs{
		retryResolve:         retryHostnameResolveAfter,
		probesBeforeQuit:     probesBeforeQuit,
		timeout:              timeout,
		secondsBetweenProbes: secondsBetweenProbes,
		intName:              interfaceName,
		showFailuresOnly:     showFailuresOnly,
		showSourceAddress:    showSourceAddress,
		args:                 args,
	}

	setGenericArgs(tcping, genericArgs)
}

/*
permuteArgs permute args for flag parsing stops just before the first non-flag argument.

see: https://pkg.go.dev/flag
*/
func permuteArgs(args []string) {
	var flagArgs []string
	var nonFlagArgs []string

	for i := 0; i < len(args); i++ {
		v := args[i]
		if v[0] == '-' {
			var optionName string
			if v[1] == '-' {
				optionName = v[2:]
			} else {
				optionName = v[1:]
			}
			switch optionName {
			case "c":
				fallthrough
			case "t":
				fallthrough
			case "db":
				fallthrough
			case "I":
				fallthrough
			case "i":
				fallthrough
			case "csv":
				fallthrough
			case "r":
				/* out of index */
				if len(args) <= i+1 {
					usage()
				}
				/* the next flag has come */
				optionVal := args[i+1]
				if optionVal[0] == '-' {
					usage()
				}
				flagArgs = append(flagArgs, args[i:i+2]...)
				i++
			default:
				flagArgs = append(flagArgs, args[i])
			}
		} else {
			nonFlagArgs = append(nonFlagArgs, args[i])
		}
	}
	permutedArgs := append(flagArgs, nonFlagArgs...)

	/* replace args */
	for i := 0; i < len(args); i++ {
		args[i] = permutedArgs[i]
	}
}

// newNetworkInterface uses the 1st ip address of the interface
// if any err occurs it calls `tcpStats.printError` and exits with status code 1.
// or return `networkInterface`
func newNetworkInterface(tcping *tcping, netInterface string) networkInterface {
	var interfaceAddress net.IP

	interfaceAddress = net.ParseIP(netInterface)

	if interfaceAddress == nil {
		ief, err := net.InterfaceByName(netInterface)
		if err != nil {
			tcping.printError("接口 %s 未找到", netInterface)
			os.Exit(1)
		}

		addrs, err := ief.Addrs()
		if err != nil {
			tcping.printError("无法获取接口地址")
			os.Exit(1)
		}

		// Iterating through the available addresses to identify valid IP configurations
		for _, addr := range addrs {
			if ip := addr.(*net.IPNet).IP; ip != nil {
				// netip.Addr
				nipAddr, err := netip.ParseAddr(ip.String())
				if err != nil {
					continue
				}

				if nipAddr.Is4() && !tcping.userInput.useIPv6 {
					interfaceAddress = ip
					break
				} else if nipAddr.Is6() && !tcping.userInput.useIPv4 {
					if nipAddr.IsLinkLocalUnicast() {
						continue
					}
					interfaceAddress = ip
					break
				}
			}
		}

		if interfaceAddress == nil {
			tcping.printError("无法获取接口的IP地址")
			os.Exit(1)
		}
	}

	// Initializing a networkInterface struct and setting the 'use' field to true
	ni := networkInterface{
		use: true,
	}

	ni.remoteAddr = &net.TCPAddr{
		IP:   net.ParseIP(tcping.userInput.ip.String()),
		Port: int(tcping.userInput.port),
	}

	sourceAddr := &net.TCPAddr{
		IP: interfaceAddress,
	}

	ni.dialer = net.Dialer{
		LocalAddr: sourceAddr,
		Timeout:   tcping.userInput.timeout, // Set the timeout duration
	}

	return ni
}

// compareVersions is used to compare tcping versions
func compareVersions(v1, v2 string) int {
	parts1 := strings.Split(v1, ".")
	parts2 := strings.Split(v2, ".")

	for i := 0; i < len(parts1) && i < len(parts2); i++ {
		n1, _ := strconv.Atoi(parts1[i])
		n2, _ := strconv.Atoi(parts2[i])

		if n1 < n2 {
			return -1
		}
		if n1 > n2 {
			return 1
		}
	}

	// for cases in which version numbers differ in length
	if len(parts1) < len(parts2) {
		return -1
	}

	if len(parts1) > len(parts2) {
		return 1
	}

	return 0
}

// checkForUpdates 检查tcping的更新版本
func checkForUpdates(tcping *tcping) {
	c := github.NewClient(nil)

	/* 来自同一IP的未认证请求每小时限制为60次。 */
	latestRelease, _, err := c.Repositories.GetLatestRelease(context.Background(), owner, repo)
	if err != nil {
		tcping.printError("检查更新失败 %s", err.Error())
		os.Exit(1)
	}

	reg := `^v?(\d+\.\d+\.\d+)$`
	latestTagName := latestRelease.GetTagName()
	latestVersion := regexp.MustCompile(reg).FindStringSubmatch(latestTagName)

	if len(latestVersion) == 0 {
		tcping.printError("检查更新失败。版本名称不符合规则: %s", latestTagName)
		os.Exit(1)
	}

	comparison := compareVersions(version, latestVersion[1])

	if comparison < 0 {
		tcping.printInfo("发现新版本 %s", latestVersion[1])
		tcping.printInfo("请从下方URL更新TCPING:")
		tcping.printInfo("https://github.com/%s/%s/releases/tag/%s",
			owner, repo, latestTagName)
	} else if comparison > 0 {
		tcping.printInfo("当前版本 %s 比最新发布版本 %s 更新",
			version, latestVersion[1])
	} else {
		tcping.printInfo("您使用的是最新版本: %s", version)
	}

	os.Exit(0)
}

// selectResolvedIP returns a single IPv4 or IPv6 address from the net.IP slice of resolved addresses
func selectResolvedIP(tcping *tcping, ipAddrs []netip.Addr) netip.Addr {
	var index int
	var ipList []netip.Addr
	var ip netip.Addr

	switch {
	case tcping.userInput.useIPv4:
		for _, ip := range ipAddrs {
			if ip.Is4() {
				ipList = append(ipList, ip)
			}
			// static builds (CGO=0) return IPv4-mapped IPv6 address
			if ip.Is4In6() {
				ipList = append(ipList, ip.Unmap())
			}
		}

		if len(ipList) == 0 {
			tcping.printError("无法找到%s的IPv4地址", tcping.userInput.hostname)
			os.Exit(1)
		}

		if len(ipList) > 1 {
			index = rand.Intn(len(ipList))
		} else {
			index = 0
		}

		ip, _ = netip.ParseAddr(ipList[index].Unmap().String())

	case tcping.userInput.useIPv6:
		for _, ip := range ipAddrs {
			if ip.Is6() {
				ipList = append(ipList, ip)
			}
		}

		if len(ipList) == 0 {
			tcping.printError("无法找到%s的IPv6地址", tcping.userInput.hostname)
			os.Exit(1)
		}

		if len(ipList) > 1 {
			index = rand.Intn(len(ipList))
		} else {
			index = 0
		}

		ip, _ = netip.ParseAddr(ipList[index].Unmap().String())

	default:
		if len(ipAddrs) > 1 {
			index = rand.Intn(len(ipAddrs))
		} else {
			index = 0
		}

		ip, _ = netip.ParseAddr(ipAddrs[index].Unmap().String())
	}

	return ip
}

// resolveHostname handles hostname resolution with a timeout value of a second
func resolveHostname(tcping *tcping) netip.Addr {
	ip, err := netip.ParseAddr(tcping.userInput.hostname)
	if err == nil {
		return ip
	}

	ctx, cancel := context.WithTimeout(context.Background(), dnsTimeout)
	defer cancel()

	ipAddrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", tcping.userInput.hostname)

	// Prevent tcping to exit if it has been running for a while
	if err != nil && (tcping.totalSuccessfulProbes != 0 || tcping.totalUnsuccessfulProbes != 0) {
		return tcping.userInput.ip
	} else if err != nil {
		tcping.printError("无法解析%s: %s", tcping.userInput.hostname, err)
		os.Exit(1)
	}

	return selectResolvedIP(tcping, ipAddrs)
}

// retryResolveHostname retries resolving a hostname after certain number of failures
func retryResolveHostname(tcping *tcping) {
	if tcping.ongoingUnsuccessfulProbes >= tcping.userInput.retryHostnameLookupAfter {
		tcping.printRetryingToResolve(tcping.userInput.hostname)
		tcping.userInput.ip = resolveHostname(tcping)
		tcping.ongoingUnsuccessfulProbes = 0
		tcping.retriedHostnameLookups++

		// At this point hostnameChanges should have len > 0, but just in case
		if len(tcping.hostnameChanges) == 0 {
			return
		}

		lastAddr := tcping.hostnameChanges[len(tcping.hostnameChanges)-1].Addr
		if lastAddr != tcping.userInput.ip {
			tcping.hostnameChanges = append(tcping.hostnameChanges, hostnameChange{
				Addr: tcping.userInput.ip,
				When: time.Now(),
			})
		}
	}
}

// newLongestTime creates LongestTime structure
func newLongestTime(startTime time.Time, duration time.Duration) longestTime {
	return longestTime{
		start:    startTime,
		end:      startTime.Add(duration),
		duration: duration,
	}
}

// calcMinAvgMaxRttTime calculates min, avg and max RTT values
func calcMinAvgMaxRttTime(timeArr []float32) rttResult {
	var sum float32
	var result rttResult

	arrLen := len(timeArr)
	// rttResults.min = ^uint(0.0)
	if arrLen > 0 {
		result.min = timeArr[0]
	}

	for i := 0; i < arrLen; i++ {
		sum += timeArr[i]

		if timeArr[i] > result.max {
			result.max = timeArr[i]
		}

		if timeArr[i] < result.min {
			result.min = timeArr[i]
		}
	}

	if arrLen > 0 {
		result.hasResults = true
		result.average = sum / float32(arrLen)
	}

	return result
}

// calcLongestUptime calculates the longest uptime and sets it to tcpStats.
func calcLongestUptime(tcping *tcping, duration time.Duration) {
	if tcping.startOfUptime.IsZero() || duration == 0 {
		return
	}

	longestUptime := newLongestTime(tcping.startOfUptime, duration)

	// It means it is the first time we're calling this function
	if tcping.longestUptime.end.IsZero() {
		tcping.longestUptime = longestUptime
		return
	}

	if longestUptime.duration >= tcping.longestUptime.duration {
		tcping.longestUptime = longestUptime
	}
}

// calcLongestDowntime calculates the longest downtime and sets it to tcpStats.
func calcLongestDowntime(tcping *tcping, duration time.Duration) {
	if tcping.startOfDowntime.IsZero() || duration == 0 {
		return
	}

	longestDowntime := newLongestTime(tcping.startOfDowntime, duration)

	// It means it is the first time we're calling this function
	if tcping.longestDowntime.end.IsZero() {
		tcping.longestDowntime = longestDowntime
		return
	}

	if longestDowntime.duration >= tcping.longestDowntime.duration {
		tcping.longestDowntime = longestDowntime
	}
}

// nanoToMillisecond returns an amount of milliseconds from nanoseconds.
// Using duration.Milliseconds() is not an option, because it drops
// decimal points, returning an int.
func nanoToMillisecond(nano int64) float32 {
	return float32(nano) / float32(time.Millisecond)
}

// secondsToDuration returns the corresponding duration from seconds expressed with a float.
func secondsToDuration(seconds float64) time.Duration {
	return time.Duration(1000*seconds) * time.Millisecond
}

// maxDuration is the implementation of the math.Max function for time.Duration types.
// returns the longest duration of x or y.
func maxDuration(x, y time.Duration) time.Duration {
	if x > y {
		return x
	}
	return y
}

// handleConnError processes failed probes
func (t *tcping) handleConnError(connTime time.Time, elapsed time.Duration) {
	if !t.destWasDown {
		t.startOfDowntime = connTime
		uptime := t.startOfDowntime.Sub(t.startOfUptime)
		calcLongestUptime(t, uptime)
		t.startOfUptime = time.Time{}
		t.destWasDown = true
	}

	t.totalDowntime += elapsed
	t.lastUnsuccessfulProbe = connTime
	t.totalUnsuccessfulProbes++
	t.ongoingUnsuccessfulProbes++

	t.printProbeFail(
		t.userInput,
		t.ongoingUnsuccessfulProbes,
	)
}

// handleConnSuccess processes successful probes
func (t *tcping) handleConnSuccess(sourceAddr string, rtt float32, connTime time.Time, elapsed time.Duration) {
	if t.destWasDown {
		t.startOfUptime = connTime
		downtime := t.startOfUptime.Sub(t.startOfDowntime)
		calcLongestDowntime(t, downtime)
		t.printTotalDownTime(downtime)
		t.startOfDowntime = time.Time{}
		t.destWasDown = false
		t.ongoingUnsuccessfulProbes = 0
		t.ongoingSuccessfulProbes = 0
	}

	if t.startOfUptime.IsZero() {
		t.startOfUptime = connTime
	}

	t.totalUptime += elapsed
	t.lastSuccessfulProbe = connTime
	t.totalSuccessfulProbes++
	t.ongoingSuccessfulProbes++
	t.rtt = append(t.rtt, rtt)

	if !t.userInput.showFailuresOnly {
		t.printProbeSuccess(
			sourceAddr,
			t.userInput,
			t.ongoingSuccessfulProbes,
			rtt,
		)
	}
}

// tcpProbe pings a host, TCP style
func tcpProbe(tcping *tcping) {
	var err error
	var conn net.Conn
	connStart := time.Now()

	if tcping.userInput.networkInterface.use {
		// dialer already contains the timeout value
		conn, err = tcping.userInput.networkInterface.dialer.Dial("tcp", tcping.userInput.networkInterface.remoteAddr.String())
	} else {
		ipAndPort := netip.AddrPortFrom(tcping.userInput.ip, tcping.userInput.port)
		conn, err = net.DialTimeout("tcp", ipAndPort.String(), tcping.userInput.timeout)
	}

	connDuration := time.Since(connStart)
	rtt := nanoToMillisecond(connDuration.Nanoseconds())

	elapsed := maxDuration(connDuration, tcping.userInput.intervalBetweenProbes)

	if err != nil {
		tcping.handleConnError(connStart, elapsed)
	} else {
		tcping.handleConnSuccess(conn.LocalAddr().String(), rtt, connStart, elapsed)
		conn.Close()
	}
	<-tcping.ticker.C
}

func main() {
	tcping := &tcping{}
	processUserInput(tcping)
	tcping.ticker = time.NewTicker(tcping.userInput.intervalBetweenProbes)
	defer tcping.ticker.Stop()

	signalHandler(tcping)

	tcping.printStart(tcping.userInput.hostname, tcping.userInput.port)

	stdinchan := make(chan bool)
	go monitorSTDIN(stdinchan)

	var probeCount uint
	for {
		if tcping.userInput.shouldRetryResolve {
			retryResolveHostname(tcping)
		}

		tcpProbe(tcping)

		select {
		case pressedEnter := <-stdinchan:
			if pressedEnter {
				tcping.printStats()
			}
		default:
		}

		if tcping.userInput.probesBeforeQuit != 0 {
			probeCount++
			if probeCount == tcping.userInput.probesBeforeQuit {
				shutdown(tcping)
			}
		}
	}
}