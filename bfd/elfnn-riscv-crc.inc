/* crc32.c
   Copyright (C) 2009-2020 Free Software Foundation, Inc.

   This file is part of the libiberty library.

   This file is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   In addition to the permissions in the GNU General Public License, the
   Free Software Foundation gives you unlimited permission to link the
   compiled version of this file into combinations with other programs,
   and to distribute those combinations without any restriction coming
   from the use of this file.  (The General Public License restrictions
   do apply in other respects; for example, they cover modification of
   the file, and distribution when not linked into a combined
   executable.)

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street - Fifth Floor, Boston, MA 02110-1301, USA.
*/

/* I have forked this file for the moment since it is not yet clear whether
   this should live inside elfnn-riscv.c or not.  */

/* For more information on CRC, see, e.g.,
   http://www.ross.net/crc/download/crc_v3.txt.  */


static unsigned int bitrev32(unsigned int x) {
  x = (x & 0x55555555) << 1  | (x & 0xaaaaaaaa) >> 1;
  x = (x & 0x33333333) << 2  | (x & 0xcccccccc) >> 2;
  x = (x & 0x0f0f0f0f) << 4  | (x & 0xf0f0f0f0) >> 4;
  x = (x & 0x00ff00ff) << 8  | (x & 0xff00ff00) >> 8;
  x = (x & 0x0000ffff) << 16 | (x & 0xffff0000) >> 16;
  return x;
}

static unsigned char bitrev8(unsigned char x) {
  x = (x & 0x55) << 1 | (x & 0xaa) >> 1;
  x = (x & 0x33) << 2 | (x & 0xcc) >> 2;
  x = (x & 0x0f) << 4 | (x & 0xf0) >> 4;
  return x;
}

/* Array for holding the table for the CRC.  */
static unsigned int crc32_table[256];

/* Update the crc32_table for a given polynomial.  */
static void update_crc32_table(unsigned poly)
{
     unsigned int i, j, k;
     unsigned int c;

     for (k = 0; k < 256; k++)
       {
         i = k;
	 for (c = i << 24, j = 8; j > 0; --j)
	   c = c & 0x80000000 ? (c << 1) ^ poly : (c << 1);
	 crc32_table[k] = c;
       }
}

/*

@deftypefn Extension {unsigned int} crc32_custom (const unsigned char *@var{buf}, @
  int @var{len}, unsigned int @var{init}, unsigned int @var{poly})

Compute the 32-bit CRC of @var{buf} which has length @var{len}.  The
starting value is @var{init}; this may be used to compute the CRC of
data split across multiple buffers by passing the return value of each
call as the @var{init} parameter of the next.

This is used by the @command{gdb} remote protocol for the @samp{qCRC}
command.  In order to get the same results as gdb for a block of data,
you must pass the first CRC parameter as @code{0xffffffff}.

This CRC can be specified as:

  Width  : 32
  Poly   : variable @var{poly}
  Init   : parameter, typically 0xffffffff
  RefIn  : false
  RefOut : false
  XorOut : 0

This differs from the "standard" CRC-32 algorithm in that the values
are not reflected, and there is no final XOR value.  These differences
make it easy to compose the values of multiple blocks.

@end deftypefn

*/

static unsigned int last_poly = 0;

static unsigned int
xcrc32_custom (const unsigned char *buf, int len, unsigned int init,
               unsigned int poly, unsigned int xorout, int refin, int refout)
{
  if (last_poly != poly)
  {
    update_crc32_table (poly);
    last_poly = poly;
  }

  unsigned int crc = init;
  while (len--)
    {
      if (refin)
	crc = (crc << 8) ^ crc32_table[((crc >> 24) ^ (bitrev8 (*buf))) & 255];
      else
	crc = (crc << 8) ^ crc32_table[((crc >> 24) ^ *buf) & 255];
      buf++;
    }

  if (refout)
    crc = bitrev32 (crc);

  crc ^= xorout;

  return crc;
}
