#!/usr/bin/python

import sys
import sqlite3
import getopt
import operator
from Tkinter import *

class executionBlock:
  def __init__(self,offset,instr):
    self.instructionList = [instr]
    self.startOffset = offset
    self.length = len(instr) / 2
    self.runTimes = 1
    
  def append(self,item):
    self.instructionList.append(item)
  
  # adding two blocks together
  def __iadd__(self,other):
    self.instructionList.append(other.instructionList)
    return self

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
    if line[0] == '-' or line[0] == '+':
      try:
        items = line.split(':')
        offset = int(items[2],16)
        thread = int(items[1],16)
        instr = items[3]
        disasm = ":".join(items[4:])
        c.execute("insert into instructions values (?,?,?,?,?,?)",(latestBinary,thread,offset,instr,disasm,line[0]))
        instructionCount += 1
      except:
        print "E:%s" % line
        sys.exit(0)
    elif line[0] == 'C':
      try:
        items = line.split(':')
        offset = int(items[2],16)
        thread = int(items[1],16)
        instr = ":".join(items[3:])
        c.execute("insert into instructions values (?,?,?,?,?,?)",(latestBinary,thread,offset,"CALL",instr,line[0]))
        callCount += 1
      except:
        print "E:%s" % line
        sys.exit(0)
    elif line[0] == 'B':
      try:
        items = line.split(':')
        modname = items[1]
        base = int(items[2],16)
        end = int(items[3],16)
        c.execute("insert into modules values (?,?,?,?)",(latestBinary,modname,base,end))
      except:
        print "E:%s" % line
        sys.exit(0)
    else:
      pass
  print "file %s added to db with %d instructions and %d calls" % (file,instructionCount,callCount)
  f.close()

# offset + length should be close enough to identify an execution block
def identifyBlocks(eipTupleList):
  knownBlocks = []
  knownOffsets = []
  currentBlock = None
  nextEip = 0
  for (thread,tag,offset,instr) in eipTupleList:
    if currentBlock is None:
      currentBlock = executionBlock(offset,instr)
    else:
      if tag == '+':
        currentBlock.append(instr)
        currentBlock.length += len(instr) / 2
        if (currentBlock.startOffset,currentBlock.length) in knownOffsets:
          for block in knownBlocks:
            if block.startOffset == currentBlock.startOffset and block.length == currentBlock.length:
              # just tick another block run time.  
              block.runTimes += 1
              break
        else:
          knownBlocks.append(currentBlock)
          knownOffsets.append( (currentBlock.startOffset,currentBlock.length) )
        currentBlock = None
      else:
        currentBlock.append(instr)
        currentBlock.length += len(instr) / 2
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
  c.execute("create table if not exists instructions (binary integer,thread long,offset long,instr text,disasm text,tag char)")
  c.execute("create table if not exists binaries (binary integer primary key autoincrement,binaryname text)")
  c.execute("create table if not exists modules (binary integer,modname text, start long, end long)")
  conn.commit()
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
    c.execute("select thread,tag,offset,instr from instructions where binary=%d" % binaryid)
    instrList = c.fetchall()
    knownBlocks = identifyBlocks(instrList)
    print "top 10 known blocks"
    hotBlocks = 0
    # from http://stackoverflow.com/questions/4010322/sort-a-list-of-class-instances-python
    sortedBlocks = sorted(knownBlocks, key = operator.attrgetter('runTimes'))
    for block in sortedBlocks:
      if block.runTimes > 1:
        print "+ block %08x byte len %d exec count %d" % (block.startOffset,block.length,block.runTimes)
        hotBlocks += 1
    print "hot blocks %d" % hotBlocks

if __name__ == "__main__":
  main()
