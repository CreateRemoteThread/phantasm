#!/usr/bin/python

# snippet finder and visualisation tool
# formless

import sys
import sqlite3
import getopt

def usage():
  print "%s -d [database] -f [file] -f [file]"
  sys.exit(0);

def storeFile(c,f):
  f = open(f,"r")
  for line in f.readlines():
    if line[0] == '-':
      items = line.split(':')
      
    elif line[0] == 'C':
      items = line.split(':')
    else:
      pass
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
    dbFile == "default.db"
  conn = sqlite3.connect(dbFile)
  c = conn.cursor()
  c.execute("create table if not exists instructions (binary int,offset long,instr text,disasm text)")
  c.execute("create table if not exists binaries (binary int,binaryname text")
  for f in inFiles:
    storeFile(c,f)
  conn.commit()
  conn.close()

if __name__ == "__main__":
  main()
