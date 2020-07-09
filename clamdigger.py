#!/usr/bin/env python

# Import the email modules we'll need
import os, re, sys, argparse, datetime, subprocess


class clamdigger(object):
    def __init__(self, args):
        #self.data = pdfdata
        self.args = args
        self.input_target = self.args.input_target
        self.ret = ''
        
        pass
    
    def build_opt_string(self):
        optstr = ""
        if self.args.i or self.args.a or self.args.w or self.args.f:
            optstr = optstr + "::"
            if self.args.i:
                optstr = optstr + "i"
            if self.args.a:
                optstr = optstr + "a"
            if self.args.w:
                optstr = optstr + "w"
            if self.args.f:
                optstr = optstr + "f"            
        return optstr 
   
    def parse(self):
        strings = self.input_target.split(",")
        strings2 = []
        autostrings2 = []
        execution_primitives2 = []
        autostrings = ["InkPicture1_Painted","AutoExec","AutoOpen","Auto_Open","AutoClose","Auto_Close","AutoExit","AutoNew","DocumentOpen",
                       "Document_Open","DocumentClose","Document_Close","DocumentBeforeClose","DocumentChange","Document_New","NewDocument",
                       "Workbook_Open","WorkbookOpen","Workbook_Activate","Workbook_Close","Workbook_Deactivate"]
        execution_primitives =[".run","shell","SHCreateThread","RtlMoveMemory","WriteProcessMemory","WriteVirtualMemory","CallWindowProc",
                               "EnumResourceTypes","EnumSystemLanguageGroups","EnumUILanguages","EnumDateFormats","EnumCalendarInfo",
                               "EnumTimeFormats","SHCreateThread","GrayString","CreateTimerQueueTimer","CreateProcess","Win32_Process","MacScript","WinExec"]
        for entry in autostrings:
            autostrings2.append(entry.encode("hex"))
        for entry in execution_primitives:
            execution_primitives2.append(entry.encode("hex"))
        for entry in strings:
            if self.args.ppstr and len(entry) < 255:
                strlen = "%0.2X" % len(entry)
                strings2.append("%s%s" % (strlen,entry.encode("hex")))
            elif self.args.wide:
                i = 0
                newstr = ""
                while i < len(entry):
                   newstr = newstr + "00{0}".format(entry[i].encode("hex"))
                   i = i + 1
                strings2.append(newstr)
            else:
                if entry.lower() == "attribute vb_":
                    strings2.append("0:" + entry.encode("hex"))
                else:
                    strings2.append(entry.encode("hex"))
        sig = self.args.sname + ";Engine:81-255,Target:%s;(" % (self.args.target)
        if self.args.do_or:
            sig = sig + "("
        i = 0
        while i < len(strings2):
            if self.args.do_or:
                 sig = sig + "%s|" % (i)
            else:
                 sig = sig + "%s&" % (i)
            i = i + 1
        
        if self.args.auto:
            if self.args.do_or:
                sig = sig[:-1]
                sig = sig + ")&("
            else:
                sig = sig + "(" 
            while i < (len(strings2) + len(autostrings2)):
                sig = sig + "%s|" % (i)
                i = i + 1
            if self.args.exeprime:
                sig = sig[:-1]
                sig = sig + ")&("
                while i < (len(strings2) + len(autostrings2) + len(execution_primitives2)):
                    sig = sig + "%s|" % (i)
                    i = i + 1
            sig = sig[:-1]
            sig = sig + "));"
        elif self.args.exeprime:
            if self.args.do_or:
                sig = sig[:-1]
                sig = sig + ")&("
            else:
                sig = sig + "("
            while i < (len(strings2) + len(execution_primitives2)):
                sig = sig + "%s|" % (i)
                i = i + 1
            sig = sig[:-1]
            sig = sig + "));"
        
        else:
            sig = sig[:-1]
            sig = sig + ");"
        
        optstr = self.build_opt_string()
        optstr3b = optstr + ";"
        sig = sig +  optstr3b.join(strings2) + optstr
        if self.args.auto:
            sig = sig + ";" + "::i;".join(autostrings2) + "::i"
            if self.args.exeprime:
                sig = sig + ";" + "::i;".join(execution_primitives2) + "::i"
        elif self.args.exeprime:
            sig = sig + ";" + "::i;".join(execution_primitives2) + "::i"
        sig=re.sub(r'(?<!2a)2a2a2a2a(?!2a)',r'*',sig)
        sig=re.sub(r'(?<!3f)3f3f3f3f(?!3f)',r'??',sig)
        sig=re.sub(r'(?<!7b)7b7b7d7d(?!7d)',r'{-}',sig)
        sig=re.sub(r'(?<!70)70637265(?!65)',r'0/putyerpcrehere/',sig)
        
        self.ret = sig
        
        
        
        pass

def main():
    targetstring="""0 = any file;
1 = Portable Executable, both 32- and 64-bit.;
2 = file inside OLE2 container (e.g. image, embedded executable, VBA;
script). The OLE2 format is primarily used by MS Office and MSI installa-tion files.;
3 = HTML (normalized: whitespace transformed to spaces, tags/tag at-tributes normalized,
all lowercase), Javascript is normalized too: all strings are normalized (hex encoding
is decoded), numbers are parsed and normal-ized, local variables/function names are
normalized to n001 format, argu-ment to eval() is parsed as JS again, unescape() is handled,
some simple JS packers are handled, output is whitespace normalized.;
4 = Mail file;
5 = Graphics;
6 = ELF;
7 = ASCII text file (normalized);
8 = Unused;
9 = Mach-O files;
10 = PDF files;
11 = Flash files;
12 = Java class files;"""
    date = datetime.date.today()
    name = 'MiscreantPunch.Fill.Me.In.' + str(date).replace('-','')
    filename = name + '.ldb'
   
    parser = argparse.ArgumentParser(description='ClamDigger.py -- "https://www.youtube.com/watch?v=ioWC-sT0iZI"', formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("-t", dest="input_target", type=str, help="Target string for conversion")
    parser.add_argument("--auto",dest="auto", action="store_true", default=False, help="Add auto open/close strings if you are doing macro things")
    parser.add_argument("--target",dest="target", type=int, default=2, help="It's a clamav target, it's a number. From clamav man:\n%s" % (targetstring))
    parser.add_argument("-s", dest="sname", type=str, default='%s' % (name), help="The signame Miscreant(?:Punch|Suspicious)\.Name.Initial.Date \n\t\t default: %s" % (name))
    parser.add_argument("-i",dest="i", action="store_false", default=True, help="Disable case insensitive matches")
    parser.add_argument("-a",dest="a", action="store_true", default=False, help="Enable ascii flag default is false")
    parser.add_argument("-w",dest="w", action="store_true", default=False, help="Enable wide flag default is false")
    parser.add_argument("-f",dest="f", action="store_true", default=False, help="Enable fullword flag default is false")
    parser.add_argument("-o", dest="o", action="store_true", default=False, help="Write to an LDB file. signame.ldb")
    parser.add_argument("--oname", dest="oname", type=str, default='%s' % (filename), help="Write to an LDB file \n\t\t default: %s" % (filename))
    parser.add_argument("-x",dest="x", action="store_true", default=False, help="Execute clamscan on current directory with the ldb.")
    parser.add_argument("--or",dest="do_or", action="store_true", default=False, help="Make an or set of matches instead of and")
    parser.add_argument("--ppstr",dest="ppstr", action="store_true", default=False,help="Prepend single byte strlen")
    parser.add_argument("--wide",dest="wide", action="store_true", default=False,help="Convert all strings to wide matches useful as it seems clamav does global matching with ::w option")
    parser.add_argument("--exeprime",dest="exeprime",action="store_true",default=False,help="Add process execution primitives observed in macros")
    args = parser.parse_args()
    
    
    if len(sys.argv) == 1:
        parser.print_help()
        exit()
    res = clamdigger(args)
    res.parse()
    results = vars(res)
    
    if args.sname !=name:
        filename = args.sname + '.ldb'
    if args.oname !=filename:
        filename = args.oname
        
    
    for key in results.iterkeys():

        if key == 'ret':
            print('Example LDB file:\n\t'),
            print(results[key])
            print(args.o)
            if args.o:
                if os.path.exists(filename):
                    print('Overwriting %s' % (filename))
                    if not raw_input("Are you sure? (y/n): ").lower().strip()[:1] == "y": exit()
                    with open(filename, 'wb') as fo:
                        fo.write(results[key])
                else:
                    with open(filename, 'wb') as fo:
                        fo.write(results[key])
            if args.o and args.x:
                p0 = subprocess.Popen(['clamscan', '-d', filename, '.'], stdout=subprocess.PIPE)
                string0 = p0.communicate()[0]
                print(string0)
                
    



if __name__ == '__main__':
    main()