/* base64.c 
 *	Copyright (C) 2001 Free Software Foundation, Inc.
 *
 * This file is part of GnuPG.
 *
 * GnuPG is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GnuPG is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h> 
#include <time.h>
#include <assert.h>

#include <ksba.h>

#include "gpgsm.h"
#include "i18n.h"


/* data used by the reader callbacks */
struct reader_cb_parm_s {
  FILE *fp;
  unsigned char line[1024];
  int linelen;
  int readpos;
  int have_lf;
  unsigned long line_counter;

  int autodetect; /* try to detect the input encoding */
  int assume_pem; /* assume input encoding is PEM */
  int assume_base64; /* assume inpout is base64 encoded */

  int identified;
  int is_pem;
  int stop_seen;

  struct {
    int idx;
    unsigned char val;
    int stop_seen;
  } base64;
};


struct base64_context_s {
  struct reader_cb_parm_s rparm;
};


/* The base-64 character list */
static unsigned char bintoasc[64] = 
       "ABCDEFGHIJKLMNOPQRSTUVWXYZ" 
       "abcdefghijklmnopqrstuvwxyz" 
       "0123456789+/"; 
/* The reverse base-64 list */
static unsigned char asctobin[256] = {
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x3e, 0xff, 0xff, 0xff, 0x3f, 
  0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0xff, 0xff, 
  0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 
  0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 
  0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0xff, 0xff, 0xff, 0xff, 0xff, 
  0xff, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 
  0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 
  0x31, 0x32, 0x33, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 
  0xff, 0xff, 0xff, 0xff
};



static int
base64_reader_cb (void *cb_value, char *buffer, size_t count, size_t *nread)
{
  struct reader_cb_parm_s *parm = cb_value;
  size_t n;
  int c, c2;

  *nread = 0;
  if (!buffer)
    return -1; /* not supported */

 next:
  if (!parm->linelen)
    {
      /* read an entire line or up to the size of the buffer */
      parm->line_counter++;
      parm->have_lf = 0;
      for (n=0; n < DIM(parm->line);)
        {
          c = getc (parm->fp);
          if (c == EOF)
            {
              if (ferror (parm->fp))
                return -1;
              break; 
            }
          parm->line[n++] = c;
          if (c == '\n')
            {
              parm->have_lf = 1;
              /* FIXME: we need to skip overlong lines while detecting
                 the dashed lines */
              break;
            }
        }
      parm->linelen = n;
      if (!n)
        return -1; /* eof */
      parm->readpos = 0;
    }

  if (!parm->identified)
    {
      if (parm->line_counter == 1 && !parm->have_lf)
        {
          /* first line too long - assume DER encoding */
          parm->is_pem = 0;
        }
      else if (parm->line_counter == 1 && parm->linelen && *parm->line == 0x30)
        {
          /* the very first bytes does pretty much look like a SEQUENCE tag*/
          parm->is_pem = 0;
        }
      else if ( parm->have_lf && !strncmp (parm->line, "-----BEGIN ", 11)
                && strncmp (parm->line+11, "PGP ", 4) )
        {
          /* Fixme: we must only compare if the line really starts at
             the beginning */
          parm->is_pem = 1;
          parm->linelen = parm->readpos = 0;
        }
      else
        {
          parm->linelen = parm->readpos = 0;
          goto next;
        }
      parm->identified = 1;
      parm->base64.stop_seen = 0;
      parm->base64.idx = 0;
    }
  

  n = 0;
  if (parm->is_pem)
    {  
      if (parm->have_lf && !strncmp (parm->line, "-----END ", 9))
        { 
          parm->identified = 0;
          parm->linelen = parm->readpos = 0;
          /* let us return 0 */
        }
      else if (parm->stop_seen)
        { /* skip the rest of the line */
          parm->linelen = parm->readpos = 0;
        }
      else
        {
          int idx = parm->base64.idx;
          unsigned char val = parm->base64.val;

          while (n < count && parm->readpos < parm->linelen )
            {
              c = parm->line[parm->readpos++];
              if (c == '\n' || c == ' ' || c == '\r' || c == '\t')
                continue;
              if (c == '=')
                { /* pad character: stop */
                  if (idx == 1)
                    buffer[n++] = val; 
                  parm->stop_seen = 1;
                  break;
                }
              if( (c = asctobin[(c2=c)]) == 255 ) 
                {
                  log_error (_("invalid radix64 character %02x skipped\n"),
                             c2);
                  continue;
                }
              switch (idx) 
                {
                case 0: 
                  val = c << 2;
                  break;
                case 1: 
                  val |= (c>>4)&3;
                  buffer[n++] = val;
                  val = (c<<4)&0xf0;
                  break;
                case 2: 
                  val |= (c>>2)&15;
                  buffer[n++] = val;
                  val = (c<<6)&0xc0;
                  break;
                case 3: 
                  val |= c&0x3f;
                  buffer[n++] = val;
                  break;
                }
              idx = (idx+1) % 4;
            }
          if (parm->readpos == parm->linelen)
            parm->linelen = parm->readpos = 0;

          parm->base64.idx = idx;
          parm->base64.val = val;
        }
    }
  else
    { /* DER encoded */
      while (n < count && parm->readpos < parm->linelen)
          buffer[n++] = parm->line[parm->readpos++];
      if (parm->readpos == parm->linelen)
        parm->linelen = parm->readpos = 0;
    }

  *nread = n;
  return 0;
}



static int
simple_reader_cb (void *cb_value, char *buffer, size_t count, size_t *nread)
{
  struct reader_cb_parm_s *parm = cb_value;
  size_t n;
  int c = 0;

  *nread = 0;
  if (!buffer)
    return -1; /* not supported */

  for (n=0; n < count; n++)
    {
      c = getc (parm->fp);
      if (c == EOF)
        {
          if ( ferror (parm->fp) )
            return -1;
          if (n)
            break; /* return what we have before an EOF */
          return -1;
        }
      *(byte *)buffer++ = c;
    }

  *nread = n;
  return 0;
}





/* Create a reader for the given file descriptor.  Depending on the
   control information an input decoding is automagically choosen.
   The function returns a Base64Context object which must be passed to
   the gpgme_destroy_reader function.  The created KsbaReader object
   is also returned, but the caller must not call the
   ksba_reader_release function on. */
int
gpgsm_create_reader (Base64Context *ctx,
                     CTRL ctrl, FILE *fp, KsbaReader *r_reader)
{
  int rc;
  KsbaReader r;

  *r_reader = NULL;
  *ctx = xtrycalloc (1, sizeof **ctx);
  if (!*ctx)
    return seterr (Out_Of_Core);

  r = ksba_reader_new ();
  if (!r)
    {
      xfree (*ctx); *ctx = NULL;
      return seterr (Out_Of_Core);
    }

  (*ctx)->rparm.fp = fp;
  if (ctrl->is_pem)
    {
      (*ctx)->rparm.assume_pem = 1;
      (*ctx)->rparm.assume_base64 = 1;
      rc = ksba_reader_set_cb (r, base64_reader_cb, &(*ctx)->rparm);
    }
  else if (ctrl->is_base64)
    {
      (*ctx)->rparm.assume_base64 = 1;
      rc = ksba_reader_set_cb (r, base64_reader_cb, &(*ctx)->rparm);
    }
  else if (ctrl->autodetect_encoding)
    {
      (*ctx)->rparm.autodetect = 1;
      rc = ksba_reader_set_cb (r, base64_reader_cb, &(*ctx)->rparm);
    }
  else
      rc = ksba_reader_set_cb (r, simple_reader_cb, &(*ctx)->rparm);

  if (rc)
    {
      ksba_reader_release (r);
      xfree (*ctx); *ctx = NULL;
      return map_ksba_err (rc);
    }

  *r_reader = r;
  return 0;
}


void
gpgsm_destroy_reader (Base64Context ctx)
{
  xfree (ctx);
}



/* Create a writer for the given stream.  Depending on the control
   information an output encoding is automagically choosen.  The
   function returns a Base64Context object which must be passed to the
   gpgme_destroy_writer function.  The created KsbaWriter object is
   also returned, but the caller must not call the ksba_reader_release
   function on. */
int
gpgsm_create_writer (Base64Context *ctx,
                     CTRL ctrl, FILE *fp, KsbaWriter *r_writer)
{
  int rc;
  KsbaWriter w;

  *r_writer = NULL;
  *ctx = xtrycalloc (1, sizeof **ctx);
  if (!*ctx)
    return seterr (Out_Of_Core);

  w = ksba_writer_new ();
  if (!w)
    {
      xfree (*ctx); *ctx = NULL;
      return seterr (Out_Of_Core);
    }

  if (ctrl->create_pem || ctrl->create_base64)
    {
      return seterr (Not_Implemented);
    }
  else
    rc = ksba_writer_set_file (w, fp);

  if (rc)
    {
      ksba_writer_release (w);
      xfree (*ctx); *ctx = NULL;
      return map_ksba_err (rc);
    }

  *r_writer = w;
  return 0;
}


void
gpgsm_destroy_writer (Base64Context ctx)
{
  xfree (ctx);
}





