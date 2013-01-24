-- tested only on LUA 5.1
--
-- Simple Amalgam Grammar
--
-- Skip all lines between OPEN_SKIP and CLOSE_SKIP
-- import text from #define REPLACE_unique_name "filename"
-- import text from #include "AMALGAM_PREFIX..file.h"
-- Replace REPLACE_STATIC at the start of any line with 'static'
--
-- Inside skip blocks, you place local #includes that you don't
-- need repeated throughout the output file.
--
local OPEN_SKIP = '#define REPLACE_SKIP';
local CLOSE_SKIP = '#undef REPLACE_SKIP';
local REPLACE_FILE = '#define REPLACE_';
local REPLACE_STATIC = 'REPLACE_STATIC';
local INCLUDE = '#include "';
local MONGOOSE_FILE = 'mongoose.c';
local AMALGAM_ROOT = 'mg_core.c';
local AMALGAM_PREFIX = 'mg_';

function process_file(filename,out,depth)
  local skip = false; -- replace skip blocks
  local chew = false; -- chew blank lines
  local f = io.open(filename,"r");
  print(string.rep(" ", depth*2).."processing "..filename);
  for line in f:lines() do
    if chew and line:match("[^%s]") then
	  chew = false;
	end;
	if skip and line:sub(1,#CLOSE_SKIP) == CLOSE_SKIP  then
	  skip = false;
	  chew = true;
	end;
	if chew or skip then
	  -- do nothing
	elseif line:sub(1,#OPEN_SKIP) == OPEN_SKIP then
	  skip = true;
	elseif line:sub(1,#REPLACE_FILE) == REPLACE_FILE then
	  process_file(line:match('#define REPLACE_.*"(.*)"'), out, depth+1);
	  chew = true;
	elseif line:sub(1,#INCLUDE) == INCLUDE then
	  fn = line:match('#include "(.*)"');
	  if fn:sub(1,#AMALGAM_PREFIX) ~= AMALGAM_PREFIX then
	    out:write(line,'\n');
	  else
		process_file(fn, out, depth+1);
		chew = true;
	  end;
	else
	  if line:sub(1,#REPLACE_STATIC) == REPLACE_STATIC then
	    line = 'static'..line:sub(#REPLACE_STATIC+1);
	  end
	  out:write(line,'\n');
	end
  end
--  f:close();
end



--main
out = io.open(MONGOOSE_FILE,"w+");

process_file(AMALGAM_ROOT, out, 0);

out:close();
