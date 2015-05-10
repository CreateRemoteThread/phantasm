TEMPORARY PYTHON SCRATCHPAD

# DEPRECATED but saved incase I need it: see below.
def identifyBlocks(eipTupleList):
  knownBlocks = []
  knownOffsets = []
  currentBlock = None
  nextEip = 0
  lastThread = 0
  for (thread,tag,offset,instr) in eipTupleList:
    if currentBlock is None:
      currentBlock = executionBlock(offset,instr)
    else:
      if tag == '+' or thread != lastThread:
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
    lastThread = thread
  return knownBlocks
