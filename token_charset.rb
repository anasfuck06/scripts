#!/usr/bin/env ruby

#
## By: Erwan Le Rousseau (RandomStorm)
#
## 
# Performed an analysis of the tokens provided in the file
# and output the possible charset for each character position
##
#

require 'terminal-table'
require 'optparse'

sort = false

parser = OptionParser.new("Usage: #{$0} [options] tokens-file", 20) do |opts|
  opts.on('-s', '--sort', 'Sort the characters found') do
    sort = true
  end
end
parser.parse!

if tokens_file = ARGV[0]

  tokens           = File.readlines(tokens_file).map &:chomp
  token_length     = tokens[0].size
  charset          = Array.new(token_length, [])
  tokens_processed = 0

  charset.each_index { |index| charset[index] = [] }

  tokens.each do |token|
    token_a = token.chars.to_a

    (0..token_length-1).each do |index|
      token_char = token_a[index] || ''

      charset[index] << token_char unless charset[index].include?(token_char)
    end
    tokens_processed += 1
  end

  charset.each_index { |index| charset[index].sort! } if sort

  # Concerting columns to rows
  size     = charset.max { |r1, r2| r1.size <=> r2.size }.size
  charset.each { |r| r[size - 1] ||= nil }
  rows     = charset.transpose
  rows << :separator
  rows <<  [{ :value => "Tokens Processed: #{tokens_processed}", :colspan => token_length, :alignment => :center }]

  # Table
  headings = (1..token_length).to_a
  style    = { padding_left: 0, padding_right: 0 }
  table    = Terminal::Table.new(headings: headings, rows: rows, title: 'Character Position', style: style)

  puts table
else
  puts parser
end
