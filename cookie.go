package main

import (
	"bytes"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/hsiafan/httpdump/httpport"
	"github.com/olekukonko/tablewriter"
	"github.com/surki/hdrhistogram"
)

var (
	statsCmd    = make(chan interface{})
	cookiesChan = make(chan ck, 10000)

	reqMetrics      = make(map[string]*hdrhistogram.Histogram)
	respMetrics     = make(map[string]*hdrhistogram.Histogram)
	allCountMetrics *hdrhistogram.Histogram
	allSizeMetrics  *hdrhistogram.Histogram
	statsWg         sync.WaitGroup

	digitRegex  *regexp.Regexp
	nameRegex   *regexp.Regexp
	beamerRegex *regexp.Regexp
)

type ck struct {
	req  []*httpport.Cookie
	resp []*httpport.Cookie
}

const (
	statsCmdReport = iota
	statsCmdQuit   = iota
)

func init() {
	allSizeMetrics = hdrhistogram.New(1, 4096*1024, 3)
	allCountMetrics = hdrhistogram.New(1, 2000, 3)

	digitRegex = regexp.MustCompile(`\.[0-9]+$`)
	nameRegex = regexp.MustCompile(`.*(_reload)$`)
	beamerRegex = regexp.MustCompile(`^(_BEAMER_)([A-Z_]+)_.*?$`)
}

func initCookieAnalytics() {
	//t := time.NewTicker(5 * time.Minute)

	statsWg.Add(1)
	go func() {
		defer statsWg.Done()

		for {
			select {
			case c := <-cookiesChan:
				//fmt.Printf("Handling cookie: %v %v\n", c.req, c.resp)
				processCookies(reqMetrics, c.req)
				processCookies(respMetrics, c.resp)
				processGlobal(c.req)

			case c := <-statsCmd:
				switch c.(int) {
				case statsCmdReport:
					cookieStatsPrint()
				case statsCmdQuit:
					return
				}
			}
		}
	}()
}

func cookieAnalyticsHandler(req *httpport.Request, resp *httpport.Response) {
	if len(req.Cookies()) == 0 && len(resp.Cookies()) == 0 {
		return
	}
	select {
	case cookiesChan <- ck{req: req.Cookies(), resp: resp.Cookies()}:
	default:
		fmt.Printf("Warning: dropping cookie metrics")
	}
}

func cookieAnalyticsReport() {
	statsCmd <- statsCmdReport
}

func cookieAnalyticsFinish() {
	statsCmd <- statsCmdQuit
	statsWg.Wait()
}

// Hack: Normalize cookie names that may vary by userid, name etc to keep
// the cardinality low
func normalizeCookieName(c string) string {
	// TODO: Fold into one regex?
	n := digitRegex.ReplaceAllString(c, ".*")
	n = nameRegex.ReplaceAllString(n, "*$1")
	n = beamerRegex.ReplaceAllString(n, "$1$2*")

	return n
}

func processCookies(metrics map[string]*hdrhistogram.Histogram, cookies []*httpport.Cookie) {
	for _, c := range cookies {
		n := normalizeCookieName(c.Name)
		if _, ok := metrics[n]; !ok {
			metrics[n] = hdrhistogram.New(1, 4096*1024, 3)
		}

		metrics[n].RecordValue(int64(len(c.Value)))
	}
}

func processGlobal(cookies []*httpport.Cookie) {
	size := 0
	for _, c := range cookies {
		size += len(c.Value)
	}
	if size > 0 {
		allSizeMetrics.RecordValue(int64(size))
		allCountMetrics.RecordValue(int64(len(cookies)))
	}
}

func printStatsCookies(metrics map[string]*hdrhistogram.Histogram) {
	if len(metrics) == 0 {
		return
	}

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Name", "AvgSize", "StdDev", "Min", "Max", "Total"})
	for n, v := range metrics {
		records := []string{
			n,
			strconv.FormatFloat(v.Mean(), 'f', 2, 64),
			strconv.FormatFloat(v.StdDev(), 'f', 2, 64),
			strconv.FormatInt(v.Min(), 10),
			strconv.FormatInt(v.Max(), 10),
			strconv.FormatInt(v.TotalCount(), 10),
		}

		table.Append(records)
	}
	table.Render()
}

func printStatsClientSide() {
	if len(reqMetrics) == 0 || len(respMetrics) == 0 {
		return
	}

	clientSide := make(map[string]bool)
	for n, _ := range reqMetrics {
		if _, ok := respMetrics[n]; !ok {
			clientSide[n] = true
		}
	}

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Name"})
	for n, _ := range clientSide {
		records := []string{n}
		table.Append(records)
	}
	table.Render()
}

func printStats(m *hdrhistogram.Histogram) {
	if m.TotalCount() == 0 {
		return
	}

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Avg", "StdDev", "Min", "Max", "Total"})
	records := []string{
		strconv.FormatFloat(m.Mean(), 'f', 2, 64),
		strconv.FormatFloat(m.StdDev(), 'f', 2, 64),
		strconv.FormatInt(m.Min(), 10),
		strconv.FormatInt(m.Max(), 10),
		strconv.FormatInt(m.TotalCount(), 10),
	}
	table.Append(records)
	table.Render()
}

func printHistogram(title string, hdrhist *hdrhistogram.Histogram) {
	var bars []hdrhistogram.Bar
	b := hdrhist.Distribution()
	for _, v := range b {
		if v.Count > 0 {
			bars = append(bars, v)
		}
	}

	if len(bars) == 0 {
		return
	}

	buckets := getHistogramBuckets(bars, hdrhist.Min(), hdrhist.Max())
	if len(buckets) == 0 {
		fmt.Println("No histogram buckets")
		return
	}

	fmt.Printf("\n%v:\n", title)
	fmt.Println(getResponseHistogram(buckets))
}

func getHistogramBuckets(bars []hdrhistogram.Bar, min int64, max int64) []Bucket {
	//fmt.Printf("Histogram: Min=%v Max=%v\n", min, max)
	bc := int64(10)
	buckets := make([]int64, bc+1)
	counts := make([]int64, bc+1)
	bs := (max - min) / (bc)
	for i := int64(0); i < bc; i++ {
		buckets[i] = min + bs*(i)
	}

	buckets[bc] = max
	counts[bc] = bars[len(bars)-1].Count

	// TODO: Figure out a better way to map hdrhistogram Bars into our
	// buckets here.
	//log.Infof("=== buckets=%v bars=%v\n", buckets, len(bars))
	bi := 0
	for i := 0; i < len(bars)-1; {
		//log.Infof("From=%v To=%v Count=%v\n", bars[i].From, bars[i].To, bars[i].Count)
		if bars[i].From >= buckets[bi] && bars[i].To <= buckets[bi] {
			//log.Infof("\t Within bucket: Adding to bucket: index=%v value=%v\n", bi, buckets[bi])
			counts[bi] += bars[i].Count
			i++
		} else if bars[i].From <= buckets[bi] {
			// TODO: Properly handle overlapping buckets
			id := bi - 1
			if id < 0 {
				id = 0
			}
			counts[id] += bars[i].Count
			i++
		} else if bi < len(buckets)-1 {
			bi++
		}
	}

	res := make([]Bucket, len(buckets))
	for i := 0; i < len(buckets); i++ {
		res[i] = Bucket{
			Mark:  buckets[i],
			Count: counts[i],
		}
	}

	return res
}

func getResponseHistogram(buckets []Bucket) string {
	barChar := "■"
	var maxCount int64
	for _, b := range buckets {
		if b.Count > maxCount {
			maxCount = b.Count
		}
	}

	res := new(bytes.Buffer)
	for i := 0; i < len(buckets); i++ {
		var barLen int64
		if maxCount > 0 {
			barLen = (buckets[i].Count*40 + maxCount/2) / maxCount
		}
		res.WriteString(fmt.Sprintf("%10d [%10d]\t|%v\n", buckets[i].Mark, buckets[i].Count, strings.Repeat(barChar, int(barLen))))
	}

	return res.String()
}

type Bucket struct {
	Mark  int64
	Count int64
}

func cookieStatsPrint() {
	fmt.Printf("\n\n")

	fmt.Println("Cookies from http requests:")
	printStatsCookies(reqMetrics)
	fmt.Printf("\n\n")

	fmt.Println("Cookies from http responses:")
	printStatsCookies(respMetrics)
	fmt.Printf("\n\n")

	fmt.Println("Cookies that are likely from frontend/clientside( i.e., Cookies missing in response but found in requests):")
	printStatsClientSide()
	fmt.Printf("\n\n")

	fmt.Println("Cookie count by host:")
	printStats(allCountMetrics)
	printHistogram("Histogram of \"count\" distribution", allCountMetrics)
	fmt.Printf("\n\n")

	fmt.Println("Cookie size by host:")
	printStats(allSizeMetrics)
	printHistogram("Histogram of \"size\" distribution", allSizeMetrics)
	fmt.Printf("\n\n")
}
