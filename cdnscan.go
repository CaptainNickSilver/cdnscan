package main

import (
	"bufio"
	"bytes"
	"encoding/csv"
	"fmt"
	"log"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"


)

// Line : This structure epresents a line in standard Apache log.  Each line will be parsed into this structure for analysis
type Line struct {
	RemoteHost string
	Time       time.Time
	Request    string // GET, POST, PUT, etc
	Protocol   string // HTTP/1.1 usually
	Status     int
	Bytes      int
	Referer    string
	UserAgent  string
	URL        string
}

/* -------------------
  Parse a single line from the apache log using the regular expression supplied
------------------- */
func parseApacheLog(regex *regexp.Regexp, inpline string) *Line {
	result := regex.FindStringSubmatch(inpline)

	lineItem := new(Line)

	// grab the IP address
	lineItem.RemoteHost = result[1]

	// parse the time into a Golang time object [05/Oct/2014:04:06:21 -0500]
	value := result[2]
	layout := "02/Jan/2006:15:04:05 -0700"
	t, _ := time.Parse(layout, value)
	lineItem.Time = t

	lineItem.Request = result[3] //+ " " + result[4] + " " + result[5]

	// parse out the URL
	url := result[4]
	altURL := result[6]
	if url == "" && altURL != "" {
		url = altURL
	}
	lineItem.URL = url

	lineItem.Protocol = result[5]

	// HTTP Status code
	status, err := strconv.Atoi(result[7])
	if err != nil {
		status = 0
	}
	lineItem.Status = status

	// HTTP number of bytes
	bytes, err := strconv.Atoi(result[8])
	if err != nil {
		bytes = 0
	}
	lineItem.Bytes = bytes

	lineItem.Referer = result[9]
	lineItem.UserAgent = result[10]

	return lineItem
}



type PathSize struct {
	subpaths []*PathSize
	pathnode   string   // the name of the directory or requested file
	lastbytes  uint64   // the number of bytes in the most recent request.
	totalbytes uint64   // the total number of bytes downloaded in this path
	totalhits  uint64   // the number of times this path was requested
}

func PathSizeFactory(parent *PathSize, pathname string ) *PathSize {
	newps := new(PathSize)
	newps.pathnode = pathname
	newps.subpaths = []*PathSize {}
	if parent != nil {
		parent.subpaths = append(parent.subpaths, newps)
	}
	return newps 
}
/* --------------------------------
CDNScan
 The application will read an apache2 log file.  Every record is evaluated to see if it is a 
 static file (.jpg, .css, .json, fonts, .js).  If it is, we add it to a tree.
 The tree records the directory and subdirectory the file is in, down to the end node.
 At the end of the run, we dump out the entire tree noting the size of the bytes
 retrieved from each directory and subdirectory and file.  Any file that is retrieved only once, 
 we don't print it.  If a directory has only one object, we don't print it.  The goal is not
 to illustrate comprehensive lists of files, but to find the directories that would have the 
 biggest impact for moving to a cdn.

 The output file is the date of the input file with an extension of csv.
 The csv format is 
 size-in-butes | path | file | number requests
-------------------------------- */
func main() {

	var argct int

	if len(os.Args) < 2 {
		log.Fatalln("missing name of log file as a command line argument")
	}

	for argct = 1; argct < len(os.Args); argct++ {
		//UserMap := make(map[string]*SiteUser) // create a hash table
		PathTree := PathSizeFactory(nil, "/")

		inpfilename := os.Args[argct]

		
		fmt.Println("\nStarting processing of file ", inpfilename)

		outfilename := determine_outname(inpfilename)

		// open the output file.  We do this first because a common error in this system
		// occurs when someone (me) has the output file open when running the app
		// -- No point in starting the analysis if it fails half way through due to an I/O error
		f, err := os.Create(outfilename)
		if err != nil {
			log.Fatal("cannot create output file", err)
		}

		defer f.Close()

		w := csv.NewWriter(f)
		defer w.Flush()

		//totusers = LoadLogIntoHashTable(inpfilename, UserMap)
		ScanLogIntoTree(inpfilename, PathTree )

		//PrintCSVHeaders(w)
		PrintTreeCSV(w, PathTree)

		w.Flush()
		f.Close()

		//DumpSummaries(unhan, stupidbytes, totusers, inpfilename)

		PathTree = nil
	}
}






/* ------------
Determine Output Filename -- the name of the output file should be based on the dates in the log file, so we open the file, sample the data, and close it
------------- */
func determine_outname(inpfilename string ) string {
	file, err := os.Open(inpfilename)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	var inpline string
	var apalog *Line
	var rowct int 
	var newfilename string 

	re1 := CreateApacheRegex()

	scanner := bufio.NewScanner(file)

	rowct = 0

	for scanner.Scan() {
		inpline = scanner.Text()
		apalog = parseApacheLog(re1, inpline)
		rowct++
		if rowct > 5 {
			break;
		}
	}
	if rowct > 0 {
		newfilename = fmt.Sprintf("analysis\\%s.log.csv",apalog.Time.Format("20060102"))
	} else {
		newfilename = "errorlog"
	}
	return newfilename 
}


func CreateApacheRegex() *regexp.Regexp {

	var buffer bytes.Buffer

	buffer.WriteString(`^(\S+)\s`)                  // 1) IP
	buffer.WriteString(`\S+\s+`)                    // remote logname
	buffer.WriteString(`(?:\S+\s+)+`)               // remote user
	buffer.WriteString(`\[([^]]+)\]\s`)             // 2) date
	buffer.WriteString(`"(\S*)\s?`)                 // 3) method
	buffer.WriteString(`(?:((?:[^"]*(?:\\")?)*)\s`) // 4) URL
	buffer.WriteString(`([^"]*)"\s|`)               // 5) protocol
	buffer.WriteString(`((?:[^"]*(?:\\")?)*)"\s)`)  // 6) or, possibly URL with no protocol
	buffer.WriteString(`(\S+)\s`)                   // 7) status code
	buffer.WriteString(`(\S+)\s`)                   // 8) bytes
	buffer.WriteString(`"((?:[^"]*(?:\\")?)*)"\s`)  // 9) referrer
	buffer.WriteString(`"(.*)"$`)                   // 10) user agent

	re1, err := regexp.Compile(buffer.String())
	if err != nil {
		log.Fatalf("regexp: %s", err)
	}
	return re1
}
/* ------------
Scan Log Into Tree -
  reads in the Apache log file 
  cares only about the status code of 200
  determines if the file is a static file (note, on our site, .html is NOT a static file)
  if so, adds that file to the tree.  That's all.
------------- */
func ScanLogIntoTree(inpfilename string, pathtree *PathSize) {

	file, err := os.Open(inpfilename)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	var inpline string
	var apalog *Line
	var dumbfilecount = 0
	

	re1 := CreateApacheRegex()

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		inpline = scanner.Text()
		apalog = parseApacheLog(re1, inpline)
		if apalog.Status == 200 {
			if IsStaticResource(apalog) {
				dumbfilecount++
				statusdots(dumbfilecount)
				InsertIntoTree(strings.Split(apalog.URL,"/"), pathtree, uint64(apalog.Bytes))
			}
		}
	}

}

/* ------------
InsertIntoTree - recursive function that is called when a static file is found
     This call will traverse the tree looking for each path part, and if found, adding the bytes to that path part and descending from there
	 If the pathpart is not found, create a new one and descend from there.
	 The leaf node is always the name of the resource
------------- */

func InsertIntoTree(parts []string, pathtree *PathSize, bytes uint64) {
	if len(parts) == 0 { return }
	if parts[0] == "" {
		InsertIntoTree(parts[1:], pathtree, bytes)
		return
	}

	for idx := 0; idx < len(pathtree.subpaths); idx++ {
		if pathtree.subpaths[idx].pathnode == parts[0] {
			pathtree.totalbytes += bytes
			pathtree.lastbytes = bytes
			pathtree.totalhits++
			InsertIntoTree(parts[1:], pathtree.subpaths[idx], bytes)
			return
		}
	}
	newps := PathSizeFactory(pathtree,parts[0])
	newps.totalbytes = bytes
	newps.totalhits = 1
	pathtree.subpaths = append(pathtree.subpaths, newps)
	InsertIntoTree(parts[1:], newps, bytes)
}

/* ------------
IsStaticResource - simple parse of the requested resource to determine if it is a static file
------------- */
func IsStaticResource(apalog *Line) bool {
	pathparts := strings.Split(apalog.URL, "/")
	idx := len(pathparts)
	if idx > 0 { 
		lastitem := pathparts[idx-1]    // should be the name of a file or resource
		if len(lastitem) > 0 {          // if this is the name of a file (not a directory)
			nameparts := strings.Split(lastitem, ".") 
			if len(nameparts) > 0 {
				extension := "|" + nameparts[len(nameparts)-1] + "|" 
				if strings.Contains("|js|jpg|png|gif|css|json|", extension ) {
					return true 
				}

			}
		}

	}

	return false
}

func PrintTreeCSV(w *csv.Writer, head *PathSize) {

	PrintCSVHeaders(w)
	TraverseAndPrint(w, "", head )
}

func TraverseAndPrint(w *csv.Writer, path string, ps *PathSize) {
	if ps == nil { return }
	PrintCSVRow (w, path, ps)
	for _, sps := range ps.subpaths {
		TraverseAndPrint (w, path + "/" + sps.pathnode, sps)
	}
}

/* ------------
Print CSV Headers - print the header line to the csv file with all the various column headers
------------- */
func PrintCSVHeaders(w *csv.Writer) {
	headers := []string{"Size", "Path", "File", "Hits"}

	w.Write(headers)

}

/* ------------
Print CSV Row - Dump the values we have discovered so far into the csv output file
------------- */
func PrintCSVRow(w *csv.Writer, path string, ps *PathSize) {


	csvrecord := []string{strconv.FormatUint(ps.totalbytes, 10), path, ps.pathnode, strconv.FormatUint(ps.totalhits, 10)}                
	w.Write(csvrecord)

}


/* ----------
// show progress by emitting dots to standard out
---------- */
func statusdots(indx int) {

	if (indx & 0xFFFF) == 0 {
		fmt.Println(" ")
	}
	if (indx & 0xFFF) == 0 { //print a dot for every 2048 new users found
		fmt.Print(".")
	}
}

/* ----------
// convenience function for formatting a floating point to print
---------- */
func pf(fval float64) string {
	return strconv.FormatFloat(fval, 'f', 1, 64)
}


/* ----------
// go through a list of slices and find the last one that has any actual content in it
---------- */
func findlast(pts []string) *string {
	for pix := len(pts) - 1; pix >= 0; pix-- {
		if len(pts[pix]) > 0 {
			return &pts[pix]
		}
	}
	// we fall through if there is no actual string text in the array
	empstring := ""
	return &empstring
}

/* ----------
Simple parse function to see if a particular file extension is referenced in a string
---------- */
func MatchExtension(pathstring string, extlist string) bool {
	ext := strings.Split(pathstring, ".")
	var matchstring string = "|" + *findlast(ext) + "|"
	return strings.Contains(extlist, matchstring)

}

/* ----------
// simple "lookup before insert" routine for a string array
---------- */
func appendunique(stringlist []*string, stringitem string) ([]*string, bool) {
	stringitem = strings.Replace(stringitem, "-", " ", -1)
	for _, st := range stringlist {
		if *st == stringitem {
			return stringlist, false // item is already in the list
		}
	}
	return append(stringlist, &stringitem), true
}
