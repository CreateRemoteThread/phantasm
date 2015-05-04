#!/usr/bin/python

# 04

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

class instructionBlock:
  def __init__(self,address):
    self.address = address
    self.instructions = []

  def append(self, instruction):
    self.instructions.append(instruction)

  def __len__(self):
    return 42

def identifyBlocks(eipTupleList):
  knownBlocks = []
  currentBlock = None
  nextEip = 0
  for (eip,instr) in eipTupleList:
    if predictedEip = eip:
      predictedEip += len(instr) / 2
      currentBlock.append(instr)
    else:
      if currentBlock != None:
        knownBlocks.append(currentBlock)
        knownOffsets.append(currentBlock.offset):
  return knownBlocks

def intWithCommas(x):
  if type(x) not in [type(0), type(0L)]:
    raise TypeError("Parameter must be an integer.")
  if x < 0:
    return '-' + intWithCommas(-x)
  result = ''
  while x >= 1000:
    x, r = divmod(x, 1000)
    result = ",%03d%s" % (r, result)
  return "%d%s" % (x, result)

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
  c.execute("select binary from binaries")
  binaries = c.fetchall()
  for row in binaries:
    (binaryid,) = row
    # print "searching for %d" % binaryid
    c.execute("select count(*) from instructions where binary=%d" % binaryid)
    instructionsPerRow = c.fetchall()
    (instructionCount,) = instructionsPerRow[0]
    print "loaded %d instructions found for binary %d" % (instructionCount,binaryid)
    c.execute("select thread,offset,instr from instructions where binary=%d" % binaryid)
    instrList = c.fetchall()
    identifyBlocks(instrList)
  root = Tk()
  _graphWindow = graphWindow(root)
  root.mainloop()
  conn.close()

if __name__ == "__main__":
  main()
