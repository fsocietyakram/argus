/**
 * Minimal EXIF/JPEG and PNG builders used by tests.
 * These produce small but structurally valid containers with a TIFF block.
 */

const ascii = (value) => Buffer.from(`${value}\0`, 'latin1');

function encodeRationals(pairs) {
  const buffer = Buffer.alloc(pairs.length * 8);
  pairs.forEach(([numerator, denominator], index) => {
    buffer.writeUInt32LE(numerator, index * 8);
    buffer.writeUInt32LE(denominator, index * 8 + 4);
  });
  return buffer;
}

const entry = (tag, type, data, count) => ({
  tag,
  type,
  count: count ?? (type === 2 ? data.length : data.length / (type === 3 ? 2 : type === 4 ? 4 : type === 5 ? 8 : 1)),
  data,
});

const ifdSize = (entries) => 2 + entries.length * 12 + 4;

/** Build a directory and assign absolute offsets to out-of-line values. */
function buildIfd(entries, dataStart) {
  const sorted = [...entries].sort((a, b) => a.tag - b.tag);
  const directory = Buffer.alloc(ifdSize(sorted));
  directory.writeUInt16LE(sorted.length, 0);

  let cursor = dataStart;
  const dataChunks = [];

  sorted.forEach((item, index) => {
    const base = 2 + index * 12;
    directory.writeUInt16LE(item.tag, base);
    directory.writeUInt16LE(item.type, base + 2);
    directory.writeUInt32LE(item.count, base + 4);
    if (item.data.length <= 4) {
      item.data.copy(directory, base + 8);
    } else {
      directory.writeUInt32LE(cursor, base + 8);
      const padding = item.data.length % 2 ? Buffer.alloc(1) : Buffer.alloc(0);
      dataChunks.push(item.data, padding);
      cursor += item.data.length + padding.length;
    }
  });

  directory.writeUInt32LE(0, directory.length - 4);
  return { directory, data: Buffer.concat(dataChunks), dataLength: cursor - dataStart };
}

export function buildTiff() {
  const ifd0Entries = [
    entry(0x010f, 2, ascii('TestMake')),
    entry(0x0110, 2, ascii('TestCamera X')),
    entry(0x0112, 3, Buffer.from([1, 0])),
    entry(0x0131, 2, ascii('ArgusTest 1.0')),
    entry(0x0132, 2, ascii('2023:05:01 12:33:10')),
    entry(0x013b, 2, ascii('Test Artist')),
    entry(0x8769, 4, Buffer.alloc(4), 1),
    entry(0x8825, 4, Buffer.alloc(4), 1),
  ];
  const exifEntries = [
    entry(0x829a, 5, encodeRationals([[1, 250]])),
    entry(0x829d, 5, encodeRationals([[28, 10]])),
    entry(0x8827, 3, Buffer.from([100, 0])),
    entry(0x9003, 2, ascii('2023:05:01 12:33:10')),
    entry(
      0x9286,
      7,
      Buffer.concat([Buffer.from('ASCII\0\0\0', 'latin1'), Buffer.from('hello from test', 'latin1')]),
    ),
    entry(0xa431, 2, ascii('SN-TEST-1234')),
    entry(0xa434, 2, ascii('Test Lens 24-70mm')),
  ];
  const gpsEntries = [
    entry(0x0001, 2, ascii('N')),
    entry(0x0002, 5, encodeRationals([[12, 1], [58, 1], [1776, 100]])),
    entry(0x0003, 2, ascii('E')),
    entry(0x0004, 5, encodeRationals([[77, 1], [35, 1], [4056, 100]])),
    entry(0x0005, 1, Buffer.from([0]), 1),
    entry(0x0006, 5, encodeRationals([[920, 1]])),
    entry(0x001d, 2, ascii('2023:05:01')),
  ];

  const ifd0Offset = 8;
  const exifOffset = ifd0Offset + ifdSize(ifd0Entries);
  const gpsOffset = exifOffset + ifdSize(exifEntries);
  const dataStart = gpsOffset + ifdSize(gpsEntries);

  ifd0Entries[6].data.writeUInt32LE(exifOffset, 0);
  ifd0Entries[7].data.writeUInt32LE(gpsOffset, 0);

  const ifd0 = buildIfd(ifd0Entries, dataStart);
  const exif = buildIfd(exifEntries, dataStart + ifd0.dataLength);
  const gps = buildIfd(gpsEntries, dataStart + ifd0.dataLength + exif.dataLength);

  const header = Buffer.alloc(8);
  header.write('II', 0, 'latin1');
  header.writeUInt16LE(42, 2);
  header.writeUInt32LE(ifd0Offset, 4);

  return Buffer.concat([header, ifd0.directory, exif.directory, gps.directory, ifd0.data, exif.data, gps.data]);
}

export function buildExifJpeg() {
  const tiff = buildTiff();
  const app1Payload = Buffer.concat([Buffer.from('Exif\0\0', 'latin1'), tiff]);
  const app1Header = Buffer.alloc(4);
  app1Header[0] = 0xff;
  app1Header[1] = 0xe1;
  app1Header.writeUInt16BE(app1Payload.length + 2, 2);

  const sof = Buffer.from([
    0xff, 0xc0, 0x00, 0x11, 0x08, 0x0b, 0xb8, 0x0f, 0xa0, 0x03, 0x01, 0x11, 0x00, 0x02, 0x11,
    0x00, 0x03, 0x11, 0x00,
  ]);
  const sos = Buffer.from([
    0xff, 0xda, 0x00, 0x0c, 0x03, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x00, 0x3f, 0x00, 0x01,
    0x02, 0x03, 0xff, 0xd9,
  ]);

  return Buffer.concat([Buffer.from([0xff, 0xd8]), app1Header, app1Payload, sof, sos]);
}

export function buildPngWithMetadata() {
  const signature = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);

  const chunk = (type, data) => {
    const length = Buffer.alloc(4);
    length.writeUInt32BE(data.length, 0);
    return Buffer.concat([length, Buffer.from(type, 'latin1'), data, Buffer.alloc(4)]);
  };

  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(1, 0);
  ihdr.writeUInt32BE(1, 4);
  ihdr[8] = 8;
  ihdr[9] = 6;

  const text = Buffer.concat([
    Buffer.from('Software\0', 'latin1'),
    Buffer.from('Argus PNG Test', 'latin1'),
  ]);

  return Buffer.concat([
    signature,
    chunk('IHDR', ihdr),
    chunk('tEXt', text),
    chunk('eXIf', buildTiff()),
    chunk('IEND', Buffer.alloc(0)),
  ]);
}
