// statsprinter.go contains the logic for printing information
package main

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"time"

	"github.com/gookit/color"
)

const (
	timeFormat = "2006-01-02 15:04:05"
	hourFormat = "15:04:05"
)

// MARK: COLOR PRINTER

var (
	colorYellow      = color.Yellow.Printf
	colorGreen       = color.Green.Printf
	colorRed         = color.Red.Printf
	colorCyan        = color.Cyan.Printf
	colorLightYellow = color.LightYellow.Printf
	colorLightBlue   = color.FgLightBlue.Printf
	colorLightGreen  = color.LightGreen.Printf
	colorLightCyan   = color.LightCyan.Printf
)

type colorPrinter struct {
	showTimestamp *bool
}

func newColorPrinter(showTimestamp *bool) *colorPrinter {
	return &colorPrinter{showTimestamp: showTimestamp}
}

func (p *colorPrinter) printStart(hostname string, port uint16) {
	colorLightCyan("正在TCP探测 %s 的 %d 端口\n", hostname, port)
}

func (p *colorPrinter) printStatistics(t tcping) {
	totalPackets := t.totalSuccessfulProbes + t.totalUnsuccessfulProbes
	packetLoss := (float32(t.totalUnsuccessfulProbes) / float32(totalPackets)) * 100

	if math.IsNaN(float64(packetLoss)) {
		packetLoss = 0
	}

	/* general stats */
	if !t.destIsIP {
		colorYellow("\n--- %s (%s) TCPing 统计信息 ---\n", t.userInput.hostname, t.userInput.ip)
	} else {
		colorYellow("\n--- %s TCPing 统计信息 ---\n", t.userInput.hostname)
	}
	colorYellow("%d 个探测包发送到 %d 端口 | ", totalPackets, t.userInput.port)
	colorYellow("%d 个探测包收到, ", t.totalSuccessfulProbes)

	/* packet loss stats */
	if packetLoss == 0 {
		colorGreen("%.2f%%", packetLoss)
	} else if packetLoss > 0 && packetLoss <= 30 {
		colorLightYellow("%.2f%%", packetLoss)
	} else {
		colorRed("%.2f%%", packetLoss)
	}

	colorYellow(" 丢失\n")

	/* successful packet stats */
	colorYellow("成功探测包:   ")
	colorGreen("%d\n", t.totalSuccessfulProbes)

	/* unsuccessful packet stats */
	colorYellow("失败探测包: ")
	colorRed("%d\n", t.totalUnsuccessfulProbes)

	colorYellow("最后一次成功探测:   ")
	if t.lastSuccessfulProbe.IsZero() {
		colorRed("从未成功\n")
	} else {
		colorGreen("%v\n", t.lastSuccessfulProbe.Format(timeFormat))
	}

	colorYellow("最后一次失败探测: ")
	if t.lastUnsuccessfulProbe.IsZero() {
		colorGreen("从未失败\n")
	} else {
		colorRed("%v\n", t.lastUnsuccessfulProbe.Format(timeFormat))
	}

	/* uptime and downtime stats */
	colorYellow("总运行时间: ")
	colorGreen("  %s\n", durationToString(t.totalUptime))
	colorYellow("总暂停时间: ")
	colorRed("%s\n", durationToString(t.totalDowntime))

	/* longest uptime stats */
	if t.longestUptime.duration != 0 {
		uptime := durationToString(t.longestUptime.duration)

		colorYellow("最长连续运行时间:   ")
		colorGreen("%v ", uptime)
		colorYellow("from ")
		colorLightBlue("%v ", t.longestUptime.start.Format(timeFormat))
		colorYellow("to ")
		colorLightBlue("%v\n", t.longestUptime.end.Format(timeFormat))
	}

	/* longest downtime stats */
	if t.longestDowntime.duration != 0 {
		downtime := durationToString(t.longestDowntime.duration)

		colorYellow("最长连续暂停时间: ")
		colorRed("%v ", downtime)
		colorYellow("从 ")
		colorLightBlue("%v ", t.longestDowntime.start.Format(timeFormat))
		colorYellow("到 ")
		colorLightBlue("%v\n", t.longestDowntime.end.Format(timeFormat))
	}

	/* resolve retry stats */
	if !t.destIsIP {
		colorYellow("重试解析主机名 ")
		colorRed("%d ", t.retriedHostnameLookups)
		colorYellow("次\n")

		if len(t.hostnameChanges) >= 2 {
			colorYellow("IP 地址变更:\n")
			for i := 0; i < len(t.hostnameChanges)-1; i++ {
				colorYellow("  从 ")
				colorRed(t.hostnameChanges[i].Addr.String())
				colorYellow(" 变更到 ")
				colorGreen(t.hostnameChanges[i+1].Addr.String())
				colorYellow(" 于 ")
				colorLightBlue("%v\n", t.hostnameChanges[i+1].When.Format(timeFormat))
			}
		}
	}

	if t.rttResults.hasResults {
		colorYellow("rtt ")
		colorGreen("min")
		colorYellow("/")
		colorCyan("avg")
		colorYellow("/")
		colorRed("max: ")
		colorGreen("%.1f", t.rttResults.min)
		colorYellow("/")
		colorCyan("%.1f", t.rttResults.average)
		colorYellow("/")
		colorRed("%.1f", t.rttResults.max)
		colorYellow(" ms\n")
	}

	colorYellow("--------------------------------------\n")
	colorYellow("TCPing 开始时间: %v\n", t.startTime.Format(timeFormat))

	/* If the program was not terminated, no need to show the end time */
	if !t.endTime.IsZero() {
		colorYellow("TCPing 结束时间:   %v\n", t.endTime.Format(timeFormat))
	}

	durationTime := time.Time{}.Add(t.totalDowntime + t.totalUptime)
	colorYellow("持续时间 (HH:MM:SS): %v\n\n", durationTime.Format(hourFormat))
}

func (p *colorPrinter) printProbeSuccess(sourceAddr string, userInput userInput, streak uint, rtt float32) {
	timestamp := ""
	if *p.showTimestamp {
		timestamp = time.Now().Format(timeFormat)
	}
	if userInput.hostname == "" {
		if timestamp == "" {
			if userInput.showSourceAddress {
				colorLightGreen("Reply 从 %s 端口 %d 使用 %s TCP_conn=%d 时间=%.1f ms\n", userInput.ip.String(), userInput.port, sourceAddr, streak, rtt)
			} else {
				colorLightGreen("Reply 从 %s 端口 %d TCP_conn=%d 时间=%.1f ms\n", userInput.ip.String(), userInput.port, streak, rtt)
			}
		} else {
			if userInput.showSourceAddress {
				colorLightGreen("%s Reply 从 %s 端口 %d 使用 %s TCP_conn=%d 时间=%.1f ms\n", timestamp, userInput.ip.String(), userInput.port, sourceAddr, streak, rtt)
			} else {
				colorLightGreen("%s Reply 从 %s 端口 %d TCP_conn=%d 时间=%.1f ms\n", timestamp, userInput.ip.String(), userInput.port, streak, rtt)
			}
		}
	} else {
		if timestamp == "" {
			if userInput.showSourceAddress {
				colorLightGreen("Reply 从 %s (%s) 端口 %d 使用 %s TCP_conn=%d 时间=%.1f ms\n", userInput.hostname, userInput.ip.String(), userInput.port, sourceAddr, streak, rtt)
			} else {
				colorLightGreen("Reply 从 %s (%s) 端口 %d TCP_conn=%d 时间=%.1f ms\n", userInput.hostname, userInput.ip.String(), userInput.port, streak, rtt)
			}
		} else {
			if userInput.showSourceAddress {
				colorLightGreen("%s Reply 从 %s (%s) 端口 %d 使用 %s TCP_conn=%d 时间=%.1f ms\n", timestamp, userInput.hostname, userInput.ip.String(), userInput.port, sourceAddr, streak, rtt)
			} else {
				colorLightGreen("%s Reply 从 %s (%s) 端口 %d TCP_conn=%d 时间=%.1f ms\n", timestamp, userInput.hostname, userInput.ip.String(), userInput.port, streak, rtt)
			}
		}
	}
}

func (p *colorPrinter) printProbeFail(userInput userInput, streak uint) {
	timestamp := ""
	if *p.showTimestamp {
		timestamp = time.Now().Format(timeFormat)
	}
	if userInput.hostname == "" {
		if timestamp == "" {
			colorRed("No reply 从 %s 端口 %d TCP_conn=%d\n", userInput.ip, userInput.port, streak)
		} else {
			colorRed("%s 未收到来自 %s 端口 %d 的响应 TCP_conn=%d\n", timestamp, userInput.ip, userInput.port, streak)
		}
	} else {
		if timestamp == "" {
			colorRed("未收到来自 %s (%s) 端口 %d 的响应 TCP_conn=%d\n", userInput.hostname, userInput.ip, userInput.port, streak)
		} else {
			colorRed("%s 未收到来自 %s (%s) 端口 %d 的响应 TCP_conn=%d\n", timestamp, userInput.hostname, userInput.ip, userInput.port, streak)
		}
	}
}

func (p *colorPrinter) printTotalDownTime(downtime time.Duration) {
	colorYellow("未收到响应 %s\n", durationToString(downtime))
}

func (p *colorPrinter) printRetryingToResolve(hostname string) {
	colorLightYellow("重试解析主机名 %s\n", hostname)
}

func (p *colorPrinter) printInfo(format string, args ...any) {
	colorLightBlue(format+"\n", args...)
}

func (p *colorPrinter) printError(format string, args ...any) {
	colorRed(format+"\n", args...)
}

func (p *colorPrinter) printVersion() {
	colorGreen("TCPing 版本 %s\n", version)
}

// MARK: PLAIN PRINTER

type plainPrinter struct {
	showTimestamp *bool
}

func newPlainPrinter(showTimestamp *bool) *plainPrinter {
	return &plainPrinter{showTimestamp: showTimestamp}
}

func (p *plainPrinter) printStart(hostname string, port uint16) {
	fmt.Printf("TCPinging %s 端口 %d\n", hostname, port)
}

func (p *plainPrinter) printStatistics(t tcping) {
	totalPackets := t.totalSuccessfulProbes + t.totalUnsuccessfulProbes
	packetLoss := (float32(t.totalUnsuccessfulProbes) / float32(totalPackets)) * 100

	if math.IsNaN(float64(packetLoss)) {
		packetLoss = 0
	}

	/* general stats */
	if !t.destIsIP {
		fmt.Printf("\n--- %s (%s) TCPing 统计信息 ---\n", t.userInput.hostname, t.userInput.ip)
	} else {
		fmt.Printf("\n--- %s TCPing 统计信息 ---\n", t.userInput.hostname)
	}
	fmt.Printf("%d 个探测包 发送到 %s 端口 %d | %d 个响应包\n", totalPackets, t.userInput.hostname, t.userInput.port, t.totalSuccessfulProbes)

	/* packet loss stats */
	fmt.Printf("%.2f%% 包丢失\n", packetLoss)

	/* successful packet stats */
	fmt.Printf("%d 个成功探测包\n", t.totalSuccessfulProbes)

	/* unsuccessful packet stats */
	fmt.Printf("%d 个失败探测包\n", t.totalUnsuccessfulProbes)

	fmt.Printf("最后一个成功探测包:   ")
	if t.lastSuccessfulProbe.IsZero() {
		fmt.Printf("从未成功\n")
	} else {
		fmt.Printf("%v\n", t.lastSuccessfulProbe.Format(timeFormat))
	}

	fmt.Printf("最后一个失败探测包: ")
	if t.lastUnsuccessfulProbe.IsZero() {
		fmt.Printf("从未失败\n")
	} else {
		fmt.Printf("%v\n", t.lastUnsuccessfulProbe.Format(timeFormat))
	}

	/* uptime and downtime stats */
	fmt.Printf("总运行时间: %s\n", durationToString(t.totalUptime))
	fmt.Printf("总暂停时间: %s\n", durationToString(t.totalDowntime))

	/* longest uptime stats */
	if t.longestUptime.duration != 0 {
		uptime := durationToString(t.longestUptime.duration)

		fmt.Printf("最长连续运行时间:   ")
		fmt.Printf("%v ", uptime)
		fmt.Printf("从 %v ", t.longestUptime.start.Format(timeFormat))
		fmt.Printf("到 %v\n", t.longestUptime.end.Format(timeFormat))
	}

	/* longest downtime stats */
	if t.longestDowntime.duration != 0 {
		downtime := durationToString(t.longestDowntime.duration)

		fmt.Printf("最长连续暂停时间: %v ", downtime)
		fmt.Printf("从 %v ", t.longestDowntime.start.Format(timeFormat))
		fmt.Printf("到 %v\n", t.longestDowntime.end.Format(timeFormat))
	}

	/* resolve retry stats */
	if !t.destIsIP {
		fmt.Printf("重试解析主机名 %d 次\n", t.retriedHostnameLookups)

		if len(t.hostnameChanges) >= 2 {
			fmt.Printf("主机名解析变更:\n")
			for i := 0; i < len(t.hostnameChanges)-1; i++ {
				fmt.Printf("  从 %s", t.hostnameChanges[i].Addr.String())
				fmt.Printf(" 到 %s", t.hostnameChanges[i+1].Addr.String())
				fmt.Printf(" 于 %v\n", t.hostnameChanges[i+1].When.Format(timeFormat))
			}
		}
	}

	if t.rttResults.hasResults {
		fmt.Printf("rtt 最小/平均/最大: ")
		fmt.Printf("%.1f/%.1f/%.1f ms\n", t.rttResults.min, t.rttResults.average, t.rttResults.max)
	}

	fmt.Printf("--------------------------------------\n")
	fmt.Printf("TCPing 开始时间: %v\n", t.startTime.Format(timeFormat))

	/* If the program was not terminated, no need to show the end time */
	if !t.endTime.IsZero() {
		fmt.Printf("TCPing 结束时间:   %v\n", t.endTime.Format(timeFormat))
	}

	durationTime := time.Time{}.Add(t.totalDowntime + t.totalUptime)
	fmt.Printf("持续时间 (HH:MM:SS): %v\n\n", durationTime.Format(hourFormat))
}

func (p *plainPrinter) printProbeSuccess(sourceAddr string, userInput userInput, streak uint, rtt float32) {
	timestamp := ""
	if *p.showTimestamp {
		timestamp = time.Now().Format(timeFormat)
	}
	if userInput.hostname == "" {
		if timestamp == "" {
			if userInput.showSourceAddress {
				fmt.Printf("回复 %s 端口 %d 使用 %s TCP_conn=%d 时间=%.1f ms\n", userInput.ip.String(), userInput.port, sourceAddr, streak, rtt)
			} else {
				fmt.Printf("回复 %s 端口 %d TCP_conn=%d 时间=%.1f ms\n", userInput.ip.String(), userInput.port, streak, rtt)
			}
		} else {
			if userInput.showSourceAddress {
				fmt.Printf("%s 回复 %s 端口 %d 使用 %s TCP_conn=%d 时间=%.3f ms\n", timestamp, userInput.ip.String(), userInput.port, sourceAddr, streak, rtt)
			} else {
				fmt.Printf("%s 回复 %s 端口 %d TCP_conn=%d 时间=%.3f ms\n", timestamp, userInput.ip.String(), userInput.port, streak, rtt)
			}
		}
	} else {
		if timestamp == "" {
			if userInput.showSourceAddress {
				fmt.Printf("%s 回复 %s (%s) 端口 %d 使用 %s TCP_conn=%d 时间=%.3f ms\n", timestamp, userInput.hostname, userInput.ip.String(), userInput.port, sourceAddr, streak, rtt)
			} else {
				fmt.Printf("%s 回复 %s (%s) 端口 %d TCP_conn=%d 时间=%.3f ms\n", timestamp, userInput.hostname, userInput.ip.String(), userInput.port, streak, rtt)
			}
		} else {
			if userInput.showSourceAddress {
				fmt.Printf("%s 回复 %s (%s) 端口 %d 使用 %s TCP_conn=%d 时间=%.3f ms\n", timestamp, userInput.hostname, userInput.ip.String(), userInput.port, sourceAddr, streak, rtt)	
			} else {
				fmt.Printf("%s 回复 %s (%s) 端口 %d TCP_conn=%d 时间=%.3f ms\n", timestamp, userInput.hostname, userInput.ip.String(), userInput.port, streak, rtt)
			}
		}
	}
}

func (p *plainPrinter) printProbeFail(userInput userInput, streak uint) {
	timestamp := ""
	if *p.showTimestamp {
		timestamp = time.Now().Format(timeFormat)
	}
	if userInput.hostname == "" {
		if timestamp == "" {
			fmt.Printf("%s 没有回复 %s 端口 %d TCP_conn=%d\n", timestamp, userInput.ip, userInput.port, streak)
		} else {
			fmt.Printf("%s 没有回复 %s 端口 %d TCP_conn=%d\n", timestamp, userInput.ip, userInput.port, streak)
		}
	} else {
		if timestamp == "" {
			fmt.Printf("%s 没有回复 %s (%s) 端口 %d TCP_conn=%d\n", timestamp, userInput.hostname, userInput.ip, userInput.port, streak)
		} else {
			fmt.Printf("%s 没有回复 %s (%s) 端口 %d TCP_conn=%d\n", timestamp, userInput.hostname, userInput.ip, userInput.port, streak)
		}
	}
}

func (p *plainPrinter) printTotalDownTime(downtime time.Duration) {
	fmt.Printf("%s 没有回复任何内容\n", durationToString(downtime))
}

func (p *plainPrinter) printRetryingToResolve(hostname string) {
	fmt.Printf("%s 重试解析主机名 %s\n", time.Now().Format(timeFormat), hostname)
}

func (p *plainPrinter) printInfo(format string, args ...any) {
	fmt.Printf(format+"\n", args...)
}

func (p *plainPrinter) printError(format string, args ...any) {
	fmt.Printf(format+"\n", args...)
}

func (p *plainPrinter) printVersion() {
	fmt.Printf("%s TCPING 版本 %s\n", time.Now().Format(timeFormat), version)
}

// MARK: JSON PRINTER

type jsonPrinter struct {
	e *json.Encoder
}

func newJSONPrinter(withIndent bool) *jsonPrinter {
	encoder := json.NewEncoder(os.Stdout)
	if withIndent {
		encoder.SetIndent("", "\t")
	}
	return &jsonPrinter{e: encoder}
}

// print is a little helper method for p.e.Encode.
// at also sets data.Timestamp to Now().
func (p *jsonPrinter) print(data JSONData) {
	data.Timestamp = time.Now()
	p.e.Encode(data)
}

// JSONEventType is a special type, each for each method
// in the printer interface so that automatic tools
// can understand what kind of an event they've received.
type JSONEventType string

const (
	// startEvent is an event type for [printStart] method.
	startEvent JSONEventType = "start"
	// probeEvent is a general event type for both
	// [printProbeSuccess] and [printProbeFail].
	probeEvent JSONEventType = "probe"
	// retryEvent is an event type for [printRetryingToResolve] method.
	retryEvent JSONEventType = "retry"
	// retrySuccessEvent is an event type for [printTotalDowntime] method.
	retrySuccessEvent JSONEventType = "retry-success"
	// statisticsEvent is a event type for [printStatistics] method.
	statisticsEvent JSONEventType = "statistics"
	// infoEvent is a event type for [printInfo] method.
	infoEvent JSONEventType = "info"
	// versionEvent is a event type for [printVersion] method.
	versionEvent JSONEventType = "version"
	// errorEvent is a event type for [printError] method.
	errorEvent JSONEventType = "error"
)

// JSONData contains all possible fields for JSON output.
// Because one event usually contains only a subset of fields,
// other fields will be omitted in the output.
type JSONData struct {
	// Type is a mandatory field that specifies type of a message/event.
	Type JSONEventType `json:"type"`
	// Message contains a human-readable message.
	Message string `json:"message"`
	// Timestamp contains data when a message was sent.
	Timestamp time.Time `json:"timestamp"`

	// Optional fields below

	Addr                 string           `json:"addr,omitempty"`
	LocalAddr            string           `json:"local_address,omitempty"`
	Hostname             string           `json:"hostname,omitempty"`
	HostnameResolveTries uint             `json:"hostname_resolve_tries,omitempty"`
	HostnameChanges      []hostnameChange `json:"hostname_changes,omitempty"`
	DestIsIP             *bool            `json:"dst_is_ip,omitempty"`
	Port                 uint16           `json:"port,omitempty"`
	Rtt                  float32          `json:"time,omitempty"`

	// Success is a special field from probe messages, containing information
	// whether request was successful or not.
	// It's a pointer on purpose, otherwise success=false will be omitted,
	// but we still need to omit it for non-probe messages.
	Success *bool `json:"success,omitempty"`

	// Latency in ms for a successful probe messages.
	Latency float32 `json:"latency,omitempty"`

	// LatencyMin is a latency stat for the stats event.
	//
	// It's a string on purpose, as we'd like to have exactly
	// 3 decimal places without doing extra math.
	LatencyMin string `json:"latency_min,omitempty"`
	// LatencyAvg is a latency stat for the stats event.
	//
	// It's a string on purpose, as we'd like to have exactly
	// 3 decimal places without doing extra math.
	LatencyAvg string `json:"latency_avg,omitempty"`
	// LatencyMax is a latency stat for the stats event.
	//
	// It's a string on purpose, as we'd like to have exactly
	// 3 decimal places without doing extra math.
	LatencyMax string `json:"latency_max,omitempty"`

	// TotalDuration is a total amount of seconds that program was running.
	//
	// It's a string on purpose, as we'd like to have exactly
	// 3 decimal places without doing extra math.
	TotalDuration string `json:"total_duration,omitempty"`
	// StartTimestamp is used as a start time of TotalDuration for stats messages.
	StartTimestamp *time.Time `json:"start_timestamp,omitempty"`
	// EndTimestamp is used as an end of TotalDuration for stats messages.
	EndTimestamp *time.Time `json:"end_timestamp,omitempty"`

	LastSuccessfulProbe   *time.Time `json:"last_successful_probe,omitempty"`
	LastUnsuccessfulProbe *time.Time `json:"last_unsuccessful_probe,omitempty"`

	// LongestUptime in seconds.
	//
	// It's a string on purpose, as we'd like to have exactly
	// 3 decimal places without doing extra math.
	LongestUptime      string     `json:"longest_uptime,omitempty"`
	LongestUptimeEnd   *time.Time `json:"longest_uptime_end,omitempty"`
	LongestUptimeStart *time.Time `json:"longest_uptime_start,omitempty"`

	// LongestDowntime in seconds.
	//
	// It's a string on purpose, as we'd like to have exactly
	// 3 decimal places without doing extra math.
	LongestDowntime      string     `json:"longest_downtime,omitempty"`
	LongestDowntimeEnd   *time.Time `json:"longest_downtime_end,omitempty"`
	LongestDowntimeStart *time.Time `json:"longest_downtime_start,omitempty"`

	// TotalPacketLoss in seconds.
	//
	// It's a string on purpose, as we'd like to have exactly
	// 3 decimal places without doing extra math.
	TotalPacketLoss         string `json:"total_packet_loss,omitempty"`
	TotalPackets            uint   `json:"total_packets,omitempty"`
	TotalSuccessfulProbes   uint   `json:"total_successful_probes,omitempty"`
	TotalUnsuccessfulProbes uint   `json:"total_unsuccessful_probes,omitempty"`
	// TotalUptime in seconds.
	TotalUptime float64 `json:"total_uptime,omitempty"`
	// TotalDowntime in seconds.
	TotalDowntime float64 `json:"total_downtime,omitempty"`
}

// printStart prints the initial message before doing probes.
func (p *jsonPrinter) printStart(hostname string, port uint16) {
	p.print(JSONData{
		Type:     startEvent,
		Message:  fmt.Sprintf("TCPinging %s on port %d", hostname, port),
		Hostname: hostname,
		Port:     port,
	})
}

// printReply prints TCP probe replies according to our policies in JSON format.
func (p *jsonPrinter) printProbeSuccess(sourceAddr string, userInput userInput, streak uint, rtt float32) {
	var (
		// for *bool fields
		f    = false
		t    = true
		data = JSONData{
			Type:                  probeEvent,
			Hostname:              userInput.hostname,
			Addr:                  userInput.ip.String(),
			Port:                  userInput.port,
			Rtt:                   rtt,
			DestIsIP:              &t,
			Success:               &t,
			TotalSuccessfulProbes: streak,
		}
	)
	if userInput.showSourceAddress {
		data.LocalAddr = sourceAddr
	}

	if userInput.hostname != "" {
		data.DestIsIP = &f
		if userInput.showSourceAddress {
			data.Message = fmt.Sprintf("%s 回复 %s (%s) 端口 %d 使用 %s 时间=%.1f ms",
				time.Now().Format(timeFormat), userInput.hostname, userInput.ip.String(), userInput.port, sourceAddr, rtt)
		} else {
			data.Message = fmt.Sprintf("%s 回复 %s (%s) 端口 %d 时间=%.1f ms",
				time.Now().Format(timeFormat), userInput.hostname, userInput.ip.String(), userInput.port, rtt)
		}
	} else {
		if userInput.showSourceAddress {
			data.Message = fmt.Sprintf("%s 回复 %s (%s) 端口 %d 使用 %s 时间=%.1f ms",
				time.Now().Format(timeFormat), userInput.ip.String(), userInput.port, sourceAddr, rtt)
		} else {
			data.Message = fmt.Sprintf("%s 回复 %s (%s) 端口 %d 时间=%.1f ms",
				time.Now().Format(timeFormat), userInput.ip.String(), userInput.port, rtt)
		}
	}

	p.print(data)
}

func (p *jsonPrinter) printProbeFail(userInput userInput, streak uint) {
	var (
		// for *bool fields
		f    = false
		t    = true
		data = JSONData{
			Type:                    probeEvent,
			Hostname:                userInput.hostname,
			Addr:                    userInput.ip.String(),
			Port:                    userInput.port,
			DestIsIP:                &t,
			Success:                 &f,
			TotalUnsuccessfulProbes: streak,
		}
	)

	if userInput.hostname != "" {
		data.DestIsIP = &f
		data.Message = fmt.Sprintf("%s 没有回复 %s (%s) 端口 %d",
			time.Now().Format(timeFormat), userInput.hostname, userInput.ip.String(), userInput.port)
	} else {
		data.Message = fmt.Sprintf("%s 没有回复 %s (%s) 端口 %d",
			time.Now().Format(timeFormat), userInput.ip.String(), userInput.port)
	}

	p.print(data)
}

// printStatistics prints all gathered stats when program exits.
func (p *jsonPrinter) printStatistics(t tcping) {
	data := JSONData{
		Type:     statisticsEvent,
		Message:  fmt.Sprintf("%s 统计信息 %s", time.Now().Format(timeFormat), t.userInput.hostname),
		Addr:     t.userInput.ip.String(),
		Hostname: t.userInput.hostname,

		StartTimestamp:          &t.startTime,
		TotalDowntime:           t.totalDowntime.Seconds(),
		TotalPackets:            t.totalSuccessfulProbes + t.totalUnsuccessfulProbes,
		TotalSuccessfulProbes:   t.totalSuccessfulProbes,
		TotalUnsuccessfulProbes: t.totalUnsuccessfulProbes,
		TotalUptime:             t.totalUptime.Seconds(),
	}

	if len(t.hostnameChanges) > 1 {
		data.HostnameChanges = t.hostnameChanges
	}

	loss := (float32(data.TotalUnsuccessfulProbes) / float32(data.TotalPackets)) * 100
	if math.IsNaN(float64(loss)) {
		loss = 0
	}
	data.TotalPacketLoss = fmt.Sprintf("%.2f", loss)

	if !t.lastSuccessfulProbe.IsZero() {
		data.LastSuccessfulProbe = &t.lastSuccessfulProbe
	}
	if !t.lastUnsuccessfulProbe.IsZero() {
		data.LastUnsuccessfulProbe = &t.lastUnsuccessfulProbe
	}

	if t.longestUptime.duration != 0 {
		data.LongestUptime = fmt.Sprintf("%.0f", t.longestUptime.duration.Seconds())
		data.LongestUptimeStart = &t.longestUptime.start
		data.LongestUptimeEnd = &t.longestUptime.end
	}

	if t.longestDowntime.duration != 0 {
		data.LongestDowntime = fmt.Sprintf("%.0f", t.longestDowntime.duration.Seconds())
		data.LongestDowntimeStart = &t.longestDowntime.start
		data.LongestDowntimeEnd = &t.longestDowntime.end
	}

	if !t.destIsIP {
		data.HostnameResolveTries = t.retriedHostnameLookups
	}

	if t.rttResults.hasResults {
		data.LatencyMin = fmt.Sprintf("%.1f", t.rttResults.min)
		data.LatencyAvg = fmt.Sprintf("%.1f", t.rttResults.average)
		data.LatencyMax = fmt.Sprintf("%.1f", t.rttResults.max)
	}

	if !t.endTime.IsZero() {
		data.EndTimestamp = &t.endTime
	}

	totalDuration := t.totalDowntime + t.totalUptime
	data.TotalDuration = fmt.Sprintf("%.0f", totalDuration.Seconds())

	p.print(data)
}

// printTotalDownTime prints the total downtime,
// if the next retry was successful.
func (p *jsonPrinter) printTotalDownTime(downtime time.Duration) {
	p.print(JSONData{
		Type:          retrySuccessEvent,
		Message:       fmt.Sprintf("%s 没有回复 %s", time.Now().Format(timeFormat), durationToString(downtime)),
		TotalDowntime: downtime.Seconds(),
	})
}

// printRetryingToResolve print the message retrying to resolve,
// after n failed probes.
func (p *jsonPrinter) printRetryingToResolve(hostname string) {
	p.print(JSONData{
		Type:     retryEvent,
		Message:  fmt.Sprintf("%s 重试解析 %s", time.Now().Format(timeFormat), hostname),
		Hostname: hostname,
	})
}

func (p *jsonPrinter) printInfo(format string, args ...any) {
	p.print(JSONData{
		Type:    infoEvent,
		Message: fmt.Sprintf(format, args...),
	})
}

func (p *jsonPrinter) printError(format string, args ...any) {
	p.print(JSONData{
		Type:    errorEvent,
		Message: fmt.Sprintf(format, args...),
	})
}

func (p *jsonPrinter) printVersion() {
	p.print(JSONData{
		Type:    versionEvent,
		Message: fmt.Sprintf("%s TCPING 版本 %s\n", time.Now().Format(timeFormat), version),
	})
}

// durationToString creates a human-readable string for a given duration
func durationToString(duration time.Duration) string {
	hours := math.Floor(duration.Hours())
	if hours > 0 {
		duration -= time.Duration(hours * float64(time.Hour))
	}

	minutes := math.Floor(duration.Minutes())
	if minutes > 0 {
		duration -= time.Duration(minutes * float64(time.Minute))
	}

	seconds := duration.Seconds()

	switch {
	// Hours
	case hours >= 2:
		return fmt.Sprintf("%s %.0f 小时 %.0f 分钟 %.0f 秒", time.Now().Format(timeFormat), hours, minutes, seconds)
	case hours == 1 && minutes == 0 && seconds == 0:
		return fmt.Sprintf("%s %.0f 小时", time.Now().Format(timeFormat), hours)
	case hours == 1:
		return fmt.Sprintf("%s %.0f 小时 %.0f 分钟 %.0f 秒", time.Now().Format(timeFormat), hours, minutes, seconds)

	// Minutes
	case minutes >= 2:
		return fmt.Sprintf("%s %.0f 分钟 %.0f 秒", time.Now().Format(timeFormat), minutes, seconds)
	case minutes == 1 && seconds == 0:
		return fmt.Sprintf("%s %.0f 分钟", time.Now().Format(timeFormat), minutes)
	case minutes == 1:
		return fmt.Sprintf("%s %.0f 分钟 %.0f 秒", time.Now().Format(timeFormat), minutes, seconds)

	// Seconds
	case seconds == 0 || seconds == 1 || seconds >= 1 && seconds < 1.1:
		return fmt.Sprintf("%s %.0f 秒", time.Now().Format(timeFormat), seconds)
	case seconds < 1:
		return fmt.Sprintf("%s %.1f 秒", time.Now().Format(timeFormat), seconds)

	default:
		return fmt.Sprintf("%s %.0f 秒", time.Now().Format(timeFormat), seconds)
	}
}

