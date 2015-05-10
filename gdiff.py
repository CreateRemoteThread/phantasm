#!/usr/bin/python

import sys
import sqlite3
import getopt
import operator
import os
import time
import random
from Tkinter import *

# ~follow me~

class graphWindow:
  def __init__(self,parent):
    top = self.top = parent
    top.resizable(0,0)
    top.title("the blind were born this way")
    self.graphFrame = Frame(self.top,width=1200, height=400)
    self.graphFrame.pack()
    self.graphCanvas = Canvas(self.graphFrame,width=1200,height=400)
    self.graphCanvas.pack()
    
class executionBlock:
  def __init__(self,offset,instr,disasm):
    self.instrText = instr
    self.disasmText = disasm
    self.startOffset = offset
    self.length = len(instr) / 2
    self.runTimes = 1
    
  def append(self,item,disasm):
    self.instrText += item + "\n"
    self.disasmText += disasm + "\n"
    
def usage():
  print "%s [args]"
  print "   -d [database.db]: load from or save to specific database file. if not supplied, default.db"
  print "   -f [exec.run]: add a given executable to database (uniqueness checked based on modtime)"
  print "   -l: list everything from a given database file"
  print "   -g [run]: graph execution for a given run within specified db, can repeat"
  sys.exit(0);

def storeFile(c,file):
  instructionCount = 0
  callCount = 0
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
  saveBlocks(c,latestBinary)

# save blocks the first time we write to file
# TODO - integrate this with the first save to file pass, no reason for this to be duplicated effort
# TODO - this code needs a verification check
# blocks structure: (binary integer, blocknum integer, blockref integer, blockdata text, blockdisasm text)
# instr structure:  (binary integer,thread long,offset long,instr text,disasm text,tag char)
def saveBlocks(c,latestBinary):
  lastBlockNumber = 1
  eipTupleList = c.execute("select thread,tag,offset,instr,disasm from instructions where binary=%d" % latestBinary)
  eipTupleList = c.fetchall()
  # knownBlocks = identifyBlocks(instrList)
  knownBlocks = []
  knownOffsets = []
  currentBlock = None
  nextEip = 0
  lastThread = 0
  for (thread,tag,offset,instr,disasm) in eipTupleList:
    if currentBlock is None:
      currentBlock = executionBlock(offset,instr,disasm)
    else:
      if tag == '+' or lastThread != thread:
        currentBlock.append(instr,disasm)
        currentBlock.length += len(instr) / 2
        blockExists = False
        for (start, length, index) in knownOffsets:
          if currentBlock.startOffset == start and currentBlock.length == length:
            c.execute("insert into blocks values (?,?,?,?,?)",(latestBinary,lastBlockNumber,index,"",""))
            blockExists = True
            break
        if blockExists == False:          # already taken care of
          knownBlocks.append(currentBlock)
          knownOffsets.append( (currentBlock.startOffset,currentBlock.length,lastBlockNumber) )
          c.execute("insert into blocks values (?,?,?,?,?)",(latestBinary,lastBlockNumber,0,currentBlock.instrText,currentBlock.disasmText))
          lastBlockNumber += 1
        currentBlock = None
      else:
        currentBlock.append(instr,disasm)
        currentBlock.length += len(instr) / 2
    lastThread = thread
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
    pass
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
  c.execute("create table if not exists instructions (binary integer,thread long,offset long,instr text,disasm text,tag char)")
  c.execute("create table if not exists binaries (binary integer primary key autoincrement,binaryname text, friendlyname text)")
  c.execute("create table if not exists modules (binary integer,modname text, start long, end long)")
  # ----------------------------------------------------------------------------------------------- #
  # THE BLOCKS TABLE OF DESTINY                                                                     #
  # ----------------------------------------------------------------------------------------------- #
  # CREATE TABLE IF NOT EXISTS Blocks(                                                              #
  #  BINARY INTEGER                     -- binds block to binary                                    #
  #  BLOCKNUM INTEGER                   -- secondary key - unique id for blocks in an exe           #
  #  BLOCKREF INTEGER                   -- self-reference (i.e. if not 0, this block exists)        #
  #  BLOCKDATA TEXT                     -- blob of block's instructions                             #
  #  BLOCKDISASM TEXT                   -- blob of disassembled block                               #
  # )                                                                                               #
  # ----------------------------------------------------------------------------------------------- #
  c.execute("create table if not exists blocks (binary integer, blocknum integer, blockref integer, blockdata text, blockdisasm text)")
  conn.commit()
  for f in inFiles:
    storeFile(c,f)
    conn.commit()
  conn.commit()
  if operationListBinaries:
    listBinaries(c)
  if operationGraphBinaries:
    graphBinaries(c,graphRuns)
  #c.execute("select binary from binaries")
  #binaries = c.fetchall()
  return
  #for row in binaries:
  #  (binaryid,) = row
  #  # print "searching for %d" % binaryid
  #  c.execute("select count(*) from instructions where binary=%d" % binaryid)
  #  instructionsPerRow = c.fetchall()
  #  (instructionCount,) = instructionsPerRow[0]
  #  print "loaded %d instructions found for binary %d" % (instructionCount,binaryid)
  #  c.execute("select thread,tag,offset,instr from instructions where binary=%d" % binaryid)
  #  instrList = c.fetchall()
  #  knownBlocks = identifyBlocks(instrList)
  #  print "top known blocks"
  #  hotBlocks = 0
  #  # from http://stackoverflow.com/questions/4010322/sort-a-list-of-class-instances-python
  #  sortedBlocks = sorted(knownBlocks, key = operator.attrgetter('runTimes'))
  #  for block in sortedBlocks:
  #    if block.runTimes > 1:
  #      print "+ block %08x byte len %d exec count %d" % (block.startOffset,block.length,block.runTimes)
  #      hotBlocks += 1
  #  print "hot blocks %d" % hotBlocks
  #root = Tk()
  #mainWindow = execGraph(root)
  #root.mainloop()

if __name__ == "__main__":
  main()
