/* compress.c - zstd compress filter
 * Copyright (C) 2003, 2004 Free Software Foundation, Inc.
 * Copyright (C) 2018 Free Software Foundation, Inc.
 *
 * This file is part of GnuPG.
 *
 * GnuPG is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * GnuPG is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 */

#include <config.h>
#include <string.h>
#include <stdio.h> /* Early versions of bzlib (1.0) require stdio.h */

#include "gpg.h"
#include "../common/util.h"
#include <zstd.h>

#include "packet.h"
#include "filter.h"
#include "main.h"
#include "options.h"

/* Note that the code in compress.c is nearly identical to the code
   here, so if you fix a bug here, look there to see if a matching bug
   needs to be fixed.  I tried to have one set of functions that could
   do ZIP, ZLIB, and BZIP2, but it became dangerously unreadable with
   #ifdefs and if(algo) -dshaw */

typedef struct {
    ZSTD_CStream const *cs;
    ZSTD_DStream const *ds;
    ZSTD_outBuffer *out;
    ZSTD_inBuffer  *in;
} zstd_context_t;

static void
init_compress( compress_filter_context_t *zfx, zstd_context_t *zctx )
{

    int rc;
    int level;

    if( opt.zstd_compress_level >= 1 && opt.zstd_compress_level <= 19 )
        level = opt.zstd_compress_level;
    else if( opt.zstd_compress_level == -1 )
        level = 1; /* no particular reason, but it seems reasonable */
    else
    {
        log_error("invalid compression level; using default level\n");
        level = 3;
    }

    zctx->cs = ZSTD_createCStream();
    if (!zctx->cs) {
        fprintf(stderr, "ZSTD_createCStream() error \n");
        exit(10);
    }

    rc=ZSTD_initCStream(zctx->cs,level);
    if (ZSTD_isError(rc))
        log_fatal("zstd problem: %d\n",rc);

    zctx->in->pos = 0;

    zctx->out->size = ZSTD_CStreamOutSize();
    zctx->out->dst = malloc( zctx->out->size );
    zctx->out->pos = 0;
}

static int
do_compress(compress_filter_context_t *zfx, zstd_context_t *zctx, int flush, IOBUF a)
{
    int rc;
    int zrc;

    while(zctx->in->pos < zctx->in->size ) {
        zrc = ZSTD_compressStream(zctx->cs, zctx->out, zctx->in);
        if (ZSTD_isError(zrc)) {
            log_error("ZSTD_compressStream() error : %s \n",
                      ZSTD_getErrorName(zrc));
            return -1;
        }

        if(zctx->out->pos > 0) {
            rc = iobuf_write(a, zctx->out->dst, zctx->out->pos);
            zctx->out->pos = 0;
            if(rc)
                log_error("zstd: iobuf_write failed\n");
        }
    }

    return 0;
}

static void
init_uncompress( compress_filter_context_t *zfx, zstd_context_t *zctx )
{
    zctx->ds = ZSTD_createDStream();
    int rc = ZSTD_initDStream(zctx->ds);
    if (ZSTD_isError(rc)) {
        log_fatal("ZSTD_initDStream() error : %s \n", ZSTD_getErrorName(rc));
    }

    zctx->in->size = ZSTD_DStreamInSize();
    zctx->in->src = xmalloc(zctx->in->size);

    zctx->in->pos = 0;
    zctx->out->pos = 0;
}

static int
do_uncompress( compress_filter_context_t *zfx, zstd_context_t *zctx,
               IOBUF a, size_t *ret_len )
{
    int zrc = -1;
    int rc= 0;
    int read = 0;


    do {
        if (zctx->in->pos == 0 || zctx->in->pos == zctx->in->size) {
            zctx->in->size = ZSTD_DStreamInSize();
            zctx->in->pos = 0;
            read = iobuf_read(a, zctx->in->src, ZSTD_DStreamInSize());
            zctx->in->size = read;
        }

        if (zctx->in->pos < zctx->in->size) {
            zctx->out->pos = 0;
            zrc = ZSTD_decompressStream(zctx->ds, zctx->out, zctx->in);
            if (ZSTD_isError(zrc)) {
                log_fatal("ZSTD_decompressStream() error : %s \n",
                          ZSTD_getErrorName(zrc));
            }

            if(zrc == 0) {
                rc = -1;
                break;
            }
        }
    } while(zctx->out->pos == 0);

    *ret_len = zctx->out->pos;
    zctx->out->pos = 0;

    return rc;
}

int
compress_filter_zstd( void *opaque, int control,
                      IOBUF a, byte *buf, size_t *ret_len)
{
    compress_filter_context_t *zfx = opaque;
    zstd_context_t *zstd = zfx->opaque;
    int rc = 0;
    size_t size = *ret_len;

    if( control == IOBUFCTRL_UNDERFLOW ) {
        if( !zfx->status ) {
            zstd = zfx->opaque = xmalloc_clear( sizeof *zstd );
            zstd->in = xmalloc_clear( sizeof *(zstd->in) );
            zstd->in->pos = 0;
            zstd->out = xmalloc_clear( sizeof *(zstd->out) );
            zstd->out->pos = 0;

            init_uncompress( zfx, zstd );

            zstd->out->dst = buf;
            zstd->out->size = size;
            zfx->status = 1;
        }
        rc = do_uncompress( zfx, zstd, a, ret_len );
    }
    else if( control == IOBUFCTRL_FLUSH ) {
        if( !zfx->status ) {
            PACKET pkt;
            PKT_compressed cd;
            if(zfx->algo != COMPRESS_ALGO_ZSTD)
                BUG();
            memset( &cd, 0, sizeof cd );
            cd.len = 0;
            cd.algorithm = zfx->algo;
            /* Fixme: We should force a new CTB here:
               cd.new_ctb = zfx->new_ctb;
            */
            init_packet( &pkt );
            pkt.pkttype = PKT_COMPRESSED;
            pkt.pkt.compressed = &cd;
            if( build_packet( a, &pkt ))
                log_bug("build_packet(PKT_COMPRESSED) failed\n");

            zstd = zfx->opaque = xmalloc_clear( sizeof *zstd );
            zstd->in = xmalloc_clear( sizeof *(zstd->in) );
            zstd->out = xmalloc_clear( sizeof *(zstd->out) );

            init_compress( zfx, zstd );
            zfx->status = 2;
        }

        zstd->in->src = buf;
        zstd->in->size = size;
        zstd->in->pos = 0;
        rc = do_compress( zfx, zstd, 0, a );
    }
    else if( control == IOBUFCTRL_FREE ) {
        if( zfx->status == 1 ) {
            xfree(zstd->out);
            xfree(zstd->in);
            xfree(zstd->ds);
            xfree(zstd);

        }

        else if( zfx->status == 2 ) {
            rc = ZSTD_endStream(zstd->cs, zstd->out);
            iobuf_write(a, zstd->out->dst, zstd->out->pos);

            xfree(zstd->out);
            xfree(zstd->cs);
            xfree(zstd);
        }

        if (zfx->release)
            zfx->release (zfx);

        rc = 0;
    }

    else if( control == IOBUFCTRL_DESC ) {
        mem2str (buf, "compress_filter", *ret_len);
        rc = 0;
    }

    return rc;
}
