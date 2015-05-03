#!/usr/bin/python

# sql-based visualisation tool

import sys
import sqlite3
import getopt
from Tkinter import *

class graphWindow:
  def __init__(self,parent):
    self.parent = parent
    parent.resizable(0,0)
    parent.title("time vs graph")

def usage():
  print "%s -d [database] -f [file] -f [file]"
  sys.exit(0);

def storeFile(c,file):
  instructionCount = 0
  callCount = 0
  f = open(file,"r")
  c.execute("insert into binaries values (null,?)",(file,))
  c.execute("select max(binary) from binaries")
  latestRecord = c.fetchone()
  (latestBinary,) = latestRecord
  for line in f.readlines():
    if line[0] == '-':
      try:
        items = line.split(':')
        offset = int(items[2],16)
        thread = int(items[1],16)
        instr = items[3]
        disasm = ":".join(items[4:])
        c.execute("insert into instructions values (?,?,?,?,?)",(latestBinary,thread,offset,instr,disasm))
        instructionCount += 1
      except:
        print line
        sys.exit(0)
    elif line[0] == 'C':
      try:
        items = line.split(':')
        offset = int(items[2],16)
        thread = int(items[1],16)
        instr = ":".join(items[3:])
        c.execute("insert into instructions values (?,?,?,?,?)",(latestBinary,thread,offset,"CALL",instr))
        callCount += 1
      except:
        print line
        sys.exit(0)
    else:
      pass
  print "file %s added to db with %d instructions and %d calls" % (file,instructionCount,callCount)
  f.close()

def main():
  dbFile = None
  inFiles = []
  try:
    opts,args = getopt.getopt(sys.argv[1:],"d:f:",["database=","file="])
  except getopt.GetoptError as err:
    print str(err)
    sys.exit(0)
  for o,a in opts:
    if o in ("-d","--database"):
      dbFile = a
    elif o in ("-f","--file"):
      inFiles.append(a)
    else:
      usage()
      sys.exit(0)
  if dbFile == None:
    dbFile = "default.db"
  conn = sqlite3.connect(dbFile)
  c = conn.cursor()
  c.execute("create table if not exists instructions (binary integer,thread long,offset long,instr text,disasm text)")
  c.execute("create table if not exists binaries (binary integer primary key autoincrement,binaryname text)")
  for f in inFiles:
    storeFile(c,f)
    conn.commit()
  conn.commit()
  conn.close()
  # select root
  root = Tk()
  _graphWindow = graphWindow(root)
  root.mainloop()

if __name__ == "__main__":
  main()
