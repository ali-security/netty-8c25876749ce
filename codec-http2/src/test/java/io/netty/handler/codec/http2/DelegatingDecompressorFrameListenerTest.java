/*
 * Copyright 2025 The Netty Project
 *
 * The Netty Project licenses this file to you under the Apache License, version 2.0 (the
 * "License"); you may not use this file except in compliance with the License. You may obtain a
 * copy of the License at:
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 */
package io.netty.handler.codec.http2;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.PooledByteBufAllocator;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.handler.codec.ByteToMessageDecoder;
import io.netty.handler.codec.http.HttpHeaderNames;
import io.netty.handler.codec.http.HttpHeaderValues;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;

/**
 * Tests for the data amplification protection of {@link DelegatingDecompressorFrameListener}.
 *
 * <p>Before the fix for CVE-2025-58057 the listener wrote the whole compressed {@code DATA} frame into the
 * decompressing {@link EmbeddedChannel} and only afterwards started to drain the produced buffers one by one. All
 * decompressed buffers of a frame were therefore held in memory at the same time, which allowed a peer to amplify a
 * small compressed frame into an arbitrary amount of retained memory. The listener now forwards every decompressed
 * buffer to the delegate {@link Http2FrameListener} as soon as the decompressor produces it, so at most one
 * decompressed buffer is alive at any point in time.
 */
public class DelegatingDecompressorFrameListenerTest {

    private static final int CHUNK_SIZE = 1024 * 1024;
    private static final int NUM_CHUNKS = 256;
    // Total decompressed size is 256 MiB, so anything close to that means the decompressed data got accumulated.
    private static final int MEMORY_LIMIT = CHUNK_SIZE * 128;

    @Test
    public void testDecompressedDataIsNotAccumulated() throws Exception {
        final PooledByteBufAllocator allocator = new PooledByteBufAllocator(false);
        final RecordingFrameListener recordingListener = new RecordingFrameListener(allocator);
        final AmplifyingDecoder decoder = new AmplifyingDecoder(recordingListener);

        final Http2Connection connection = new DefaultHttp2Connection(true);
        connection.local().flowController(mock(Http2LocalFlowController.class));
        connection.remote().createStream(3, false);

        DelegatingDecompressorFrameListener frameListener =
                new DelegatingDecompressorFrameListener(connection, recordingListener) {
            @Override
            protected EmbeddedChannel newContentDecompressor(ChannelHandlerContext ctx, CharSequence contentEncoding) {
                EmbeddedChannel channel = new EmbeddedChannel(decoder);
                channel.config().setAllocator(allocator);
                return channel;
            }
        };

        EmbeddedChannel parent = new EmbeddedChannel(new ChannelInboundHandlerAdapter());
        try {
            ChannelHandlerContext ctx = parent.pipeline().firstContext();

            Http2Headers headers = new DefaultHttp2Headers();
            headers.set(HttpHeaderNames.CONTENT_ENCODING, HttpHeaderValues.GZIP);
            frameListener.onHeadersRead(ctx, 3, headers, 0, false);

            // Every single byte of the "compressed" frame explodes into CHUNK_SIZE bytes of decompressed data.
            ByteBuf data = Unpooled.buffer(NUM_CHUNKS);
            data.writeZero(NUM_CHUNKS);
            try {
                frameListener.onDataRead(ctx, 3, data, 0, true);
            } finally {
                data.release();
            }

            // All the decompressed data must have been handed over to the delegate listener...
            assertEquals(NUM_CHUNKS, recordingListener.dataReads);
            assertEquals((long) CHUNK_SIZE * NUM_CHUNKS, recordingListener.decompressedBytes);
            assertTrue(recordingListener.sawEndOfStream);

            // ... while the retained memory stays far below the total decompressed size.
            assertTrue(recordingListener.maxUsedMemory < MEMORY_LIMIT,
                    "used memory " + recordingListener.maxUsedMemory + " exceeded limit " + MEMORY_LIMIT);

            // ... because it is handed over buffer by buffer, never queuing up decompressed buffers.
            assertEquals(0, decoder.maxUndelivered, "decompressed buffers were accumulated before being forwarded");
        } finally {
            assertFalse(parent.finishAndReleaseAll());
        }
    }

    /**
     * Stands in for a real decompressor: consumes one byte of input per {@code decode(...)} call and produces a
     * {@link #CHUNK_SIZE} big buffer for it, mimicking a highly compressible payload.
     */
    private static final class AmplifyingDecoder extends ByteToMessageDecoder {
        private final RecordingFrameListener listener;
        private int produced;
        int maxUndelivered;

        AmplifyingDecoder(RecordingFrameListener listener) {
            this.listener = listener;
        }

        @Override
        protected void decode(ChannelHandlerContext ctx, ByteBuf in, List<Object> out) {
            if (!in.isReadable()) {
                return;
            }
            in.readByte();
            // Everything that was produced so far should already have been forwarded to the delegate listener.
            maxUndelivered = Math.max(maxUndelivered, produced - listener.dataReads);
            ByteBuf chunk = ctx.alloc().heapBuffer(CHUNK_SIZE);
            chunk.writeZero(CHUNK_SIZE);
            produced++;
            out.add(chunk);
        }
    }

    private static final class RecordingFrameListener extends Http2FrameAdapter {
        private final PooledByteBufAllocator allocator;
        int dataReads;
        long decompressedBytes;
        long maxUsedMemory;
        boolean sawEndOfStream;

        RecordingFrameListener(PooledByteBufAllocator allocator) {
            this.allocator = allocator;
        }

        @Override
        public int onDataRead(ChannelHandlerContext ctx, int streamId, ByteBuf data, int padding,
                              boolean endOfStream) {
            maxUsedMemory = Math.max(maxUsedMemory,
                    allocator.metric().usedHeapMemory() + allocator.metric().usedDirectMemory());
            int processed = data.readableBytes() + padding;
            if (data.isReadable()) {
                dataReads++;
                decompressedBytes += data.readableBytes();
            }
            if (endOfStream) {
                sawEndOfStream = true;
            }
            return processed;
        }
    }
}
