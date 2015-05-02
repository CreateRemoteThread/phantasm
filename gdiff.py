#!/usr/bin/python

# sql-based visualisation tool

import sys
import sqlite3
import getopt

def usage():
  print "%s -d [database] -f [file] -f [file]"
  sys.exit(0);

def storeFile(c,file):
  f = open(file,"r")
  c.execute("insert into binaries values (null,?)",(file,))
  c.execute("select max(binary) from binaries")
  latestRecord = c.fetchone()
  (latestBinary,) = latestRecord
  for line in f.readlines():
    if line[0] == '-':
      items = line.split(':')
      offset = int(items[2],16)
      thread = int(items[1],16)
      instr = items[3]
      disasm = " ".join(items[4:])
      c.execute("insert into instructions values (?,?,?,?,?)",(latestBinary,thread,offset,instr,disasm))
    elif line[0] == 'C':
      
      c.execute("insert into instructions values (?,?,?,?,?)",(latestBinary,thread,offset,instr,disasm))
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
    dbFile = "default.db"
  conn = sqlite3.connect(dbFile)
  c = conn.cursor()
  c.execute("create table if not exists instructions (binary integer,thread long,offset long,instr text,disasm text)")
  c.execute("create table if not exists binaries (binary integer primary key autoincrement,binaryname text)")
  for f in inFiles:
    storeFile(c,f)
  conn.commit()
  conn.close()

if __name__ == "__main__":
  main()
