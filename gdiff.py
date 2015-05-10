#!/usr/bin/python

import sys
import sqlite3
import getopt
import operator
import os
import time
import random
from Tkinter import *

# ~ follow me ~

class graphWindow:
  def __init__(self,parent):
    top = self.top = parent
    top.resizable(0,0)
    top.title("the blind were born this way")
    self.graphFrame = Frame(self.top,width=1200, height=400)
    self.graphFrame.pack()
    #self.graphCanvas = Canvas(self.graphFrame,width=1200,height=400)
    #self.graphCanvas.pack()

  def graphRun(self,c,friendlyname):
    processBlocks = {}
    c.execute("select binary from binaries where friendlyname = ?" , (friendlyname,))
    binaryIdTuple = c.fetchone()
    binaryId = binaryIdTuple[0]
    c.execute("select start, end from modules where binary = ? and modname = ?", (binaryId,"BASE"))
    (_start, _end) = c.fetchone()
    c.execute("select blocknum,blockref,addr,blockdata,blockdisasm,runcount from blocks where binary = ?", (binaryId,) )
    resultBlocks = c.fetchall()
    totalLength = 0
    for (blocknum,blockref,offset,instr,disasm,runcount) in resultBlocks:
      processBlocks[blocknum] = (blockref, offset, instr, disasm,runcount)
      if len(instr) == 0:
        totalLength += 1
      else:
        totalLength += len(instr) / 2
    for i in range(1,max(processBlocks.keys())):
      (blockref, offset, instr, disasm,runCount) = processBlocks[i]
      if offset >= _start and offset <= _end:
        if runCount > 1:
          print "rectangle - %08x, runs %d\n%s" % (offset - _start, runCount,disasm),
        else:
          print "line - %s" % (disasm),
    print "fetching run data for %s, %d results, %d total bytes" % (friendlyname, len(resultBlocks), totalLength)

class executionBlock:
  def __init__(self,offset,instr,disasm):
    self.instrText = instr
    self.disasmText = disasm
    self.startOffset = offset
    self.length = len(instr) / 2
    self.runTimes = 1
    
  def append(self,item,disasm):
    self.instrText += item
    self.disasmText += disasm
    
def usage():
  print "%s [args]"
  print "   -d [database.db]: load from or save to specific database file. if not supplied, default.db"
  print "   -f [exec.run]: add a given executable to database (uniqueness checked based on modtime)"
  print "   -l: list everything from a given database file"
  print "   -g [run]: graph execution for a given run within specified db, can repeat"
  sys.exit(0);

# (binary integer, blocknum integer, blockref integer, addr long, blockdata text, blockdisasm text, runcount integer)
def storeFile(c,file):
  instructionCount = 0
  modtime = time.ctime(os.path.getmtime(file))
  longFileName = "%s-%s" % (file,modtime)
  friendlyName = "%s-%04x" % (file,random.randint(0,0xFFFF))
  # try to fetch first.
  c.execute("select binary from binaries where binaryname = ?" , (longFileName,))
  binaries = c.fetchall()
  if len(binaries) > 0:
    print "%d results already found for entry %s" % (len(binaries),file)
    return
  f = open(file,"r")
  c.execute("insert into binaries values (null,?,?)",(longFileName,friendlyName))
  c.execute("select max(binary) from binaries")
  latestRecord = c.fetchone()
  (latestBinary,) = latestRecord
  lastBlockNumber = 1
  knownBlocks = []
  knownOffsets = []
  currentBlock = None
  nextEip = 0
  lastThread = 0
  runCounts = {}
  for line in f.readlines():
    if line[0] == '-' or line[0] == '+':
      try:
        items = line.split(':')
        offset = int(items[2],16)
        thread = int(items[1],16)
        instr = items[3]
        disasm = ":".join(items[4:])
        # c.execute("insert into instructions values (?,?,?,?,?,?)",(latestBinary,thread,offset,instr,disasm,line[0]))
        instructionCount += 1
      except:
        print "E:%s" % line
        sys.exit(0)
      if currentBlock is None:
        currentBlock = executionBlock(offset,instr,disasm)
      else:
        if line[0] == '+' or lastThread != thread:
          currentBlock.append(instr,disasm)
          currentBlock.length += len(instr) / 2
          blockExists = False
          for (start, length, index) in knownOffsets:
            if currentBlock.startOffset == start and currentBlock.length == length:
              # i.e. known block
              c.execute("insert into blocks values (?,?,?,?,?,?,0)",(latestBinary,lastBlockNumber,index,currentBlock.startOffset,"",""))  
              runCounts[index] += 1
              blockExists = True
              break
          if blockExists == False:          # already taken care of
            knownBlocks.append(currentBlock)
            knownOffsets.append( (currentBlock.startOffset,currentBlock.length,lastBlockNumber) )
            c.execute("insert into blocks values (?,?,?,?,?,?,1)",(latestBinary,lastBlockNumber,0,currentBlock.startOffset,currentBlock.instrText,currentBlock.disasmText))
            runCounts[lastBlockNumber] = 1
            lastBlockNumber += 1
          currentBlock = None
        else:
          currentBlock.append(instr,disasm)
          currentBlock.length += len(instr) / 2
      lastThread = thread
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
  # print "updating run counts..."
  for i in runCounts.keys():
    if runCounts[i] != 1:
      c.execute("update blocks set runcount = ? where blocknum = ?",(runCounts[i],i))
  print "file %s added to db with %d instructions" % (file,instructionCount)
  f.close()

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

def listBinaries(c):
  c.execute("select friendlyname from binaries")
  r = c.fetchall()
  for row in r:
    (fname,) = row
    print fname

# only start TK here if needed.
def graphBinaries(c,binaryList):
  root = Tk()
  g = graphWindow(root)
  for binary in binaryList:
    g.graphRun(c,binary)
  root.mainloop() # return everything
  return

def main():
  dbFile = None
  inFiles = []
  graphRuns = []
  operationListBinaries = False
  operationGraphBinaries = False
  try:
    opts,args = getopt.getopt(sys.argv[1:],"d:f:lg:",["database=","file=","list","graph="])
  except getopt.GetoptError as err:
    print str(err)
    sys.exit(0)
  for o,a in opts:
    if o in ("-d","--database"):
      dbFile = a
    elif o in ("-f","--file"):
      inFiles.append(a)
    elif o in ("-l","--list"):
      operationListBinaries = True
    elif o in ("-g","--graph"):
      operationGraphBinaries = True
      graphRuns.append(a)
    else:
      usage()
      sys.exit(0)
  if dbFile == None:
    dbFile = "default.db"
  conn = sqlite3.connect(dbFile)
  c = conn.cursor()
  # c.execute("create table if not exists instructions (binary integer,thread long,offset long,instr text,disasm text,tag char)")
  c.execute("create table if not exists binaries (binary integer primary key autoincrement,binaryname text, friendlyname text)")
  c.execute("create table if not exists modules (binary integer,modname text, start long, end long)")
  # ----------------------------------------------------------------------------------------------- #
  # THE BLOCKS TABLE OF DESTINY                                                                     #
  # ----------------------------------------------------------------------------------------------- #
  # CREATE TABLE IF NOT EXISTS Blocks(                                                              #
  #  BINARY INTEGER                     -- binds block to binary                                    #
  #  BLOCKNUM INTEGER                   -- secondary key - unique id for blocks in an exe           #
  #  BLOCKREF INTEGER                   -- self-reference (i.e. if not 0, this block exists)        #
  #  ADDR LONG                          -- where does this start                                    #
  #  BLOCKDATA TEXT                     -- blob of block's instructions                             #
  #  BLOCKDISASM TEXT                   -- blob of disassembled block                               #
  #  RUNCOUNT INTEGER                   -- times block is run (at creation)                         #
  # )                                                                                               #
  # ----------------------------------------------------------------------------------------------- #
  c.execute("create table if not exists blocks (binary integer, blocknum integer, blockref integer, addr long, blockdata text, blockdisasm text, runcount integer)")
  conn.commit()
  for f in inFiles:
    storeFile(c,f)
    conn.commit()
  conn.commit()
  if operationListBinaries:
    listBinaries(c)
  if operationGraphBinaries:
    graphBinaries(c,graphRuns)
  #binaries = c.fetchall()
  return

if __name__ == "__main__":
  main()
