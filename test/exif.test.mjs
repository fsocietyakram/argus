import test from 'node:test';
import assert from 'node:assert/strict';
import { analyzeFile, detectFormat, parseTiff, stripMetadata } from '../src/exif.mjs';
import { buildExifJpeg, buildPngWithMetadata, buildTiff } from './helpers/build-jpeg.mjs';

test('detectFormat recognises common containers and falls back to extension', () => {
  const jpeg = buildExifJpeg();
  assert.equal(detectFormat(jpeg), 'jpeg');
  assert.equal(detectFormat(buildPngWithMetadata()), 'png');
  assert.equal(detectFormat(Buffer.from('GIF89a------')), 'gif');
  assert.equal(detectFormat(Buffer.from('%PDF-1.7\n')), 'pdf');

  const heic = Buffer.concat([
    Buffer.from([0x00, 0x00, 0x00, 0x18]),
    Buffer.from('ftypheic', 'latin1'),
    Buffer.alloc(8),
  ]);
  assert.equal(detectFormat(heic), 'heic');
  assert.equal(detectFormat(Buffer.from('not an image'), 'photo.jpg'), 'jpeg');
  assert.equal(detectFormat(Buffer.from('not an image'), 'photo.unknown'), 'unknown');
});

test('analyzeFile extracts JPEG EXIF, GPS, camera fields, and risk indicators', () => {
  const result = analyzeFile(buildExifJpeg(), 'holiday.jpg');

  assert.equal(result.command, 'file');
  assert.equal(result.file.format, 'jpeg');
  assert.equal(result.file.mime, 'image/jpeg');
  assert.match(result.file.sha256, /^[a-f0-9]{64}$/);
  assert.equal(result.image.width, 4000);
  assert.equal(result.image.height, 3000);
  assert.equal(result.exif.present, true);
  assert.ok(result.exif.tagCount > 5);
  assert.equal(result.exif.camera.make, 'TestMake');
  assert.equal(result.exif.camera.model, 'TestCamera X');
  assert.equal(result.exif.camera.lensModel, 'Test Lens 24-70mm');
  assert.equal(result.exif.camera.serialNumber, 'SN-TEST-1234');
  assert.equal(result.exif.camera.artist, 'Test Artist');
  assert.equal(result.exif.timestamps.original, '2023-05-01 12:33:10');
  assert.equal(result.exif.userComment, 'hello from test');

  assert.ok(result.exif.gps, 'GPS block should be parsed');
  assert.equal(result.exif.gps.latitude, 12.9716);
  assert.equal(result.exif.gps.longitude, 77.5946);
  assert.equal(result.exif.gps.altitude, 920);
  assert.match(result.exif.gps.maps.openstreetmap, /openstreetmap\.org/);

  assert.equal(result.risk.level, 'high');
  assert.ok(result.risk.score >= 60);
  assert.ok(result.risk.findings.some((finding) => /GPS coordinates/i.test(finding.text)));
  assert.equal(result.stripSupported, true);
});

test('stripMetadata removes JPEG EXIF while keeping a valid JPEG shell', () => {
  const original = buildExifJpeg();
  const stripped = stripMetadata(original, 'holiday.jpg');

  assert.equal(stripped.ok, true);
  assert.equal(stripped.format, 'jpeg');
  assert.ok(stripped.removed.includes('EXIF (APP1)'));
  assert.ok(stripped.buffer.length < original.length);
  assert.equal(stripped.buffer[0], 0xff);
  assert.equal(stripped.buffer[1], 0xd8);

  const result = analyzeFile(stripped.buffer, 'holiday-stripped.jpg');
  assert.equal(result.exif.present, false);
  assert.equal(result.exif.gps, null);
  assert.equal(result.image.width, 4000);
});

test('PNG eXIf and tEXt metadata are parsed and stripped', () => {
  const png = buildPngWithMetadata();
  const result = analyzeFile(png, 'image.png');

  assert.equal(result.file.format, 'png');
  assert.equal(result.exif.present, true);
  assert.equal(result.exif.camera.make, 'TestMake');
  assert.equal(result.image.width, 1);
  assert.equal(result.image.height, 1);
  assert.ok(
    result.metadataText.some(
      (entry) => entry.key === 'Software' && entry.value === 'Argus PNG Test',
    ),
  );

  const stripped = stripMetadata(png, 'image.png');
  assert.equal(stripped.ok, true);
  assert.ok(stripped.removed.includes('PNG eXIf'));
  assert.ok(stripped.removed.includes('PNG tEXt'));

  const after = analyzeFile(stripped.buffer, 'image-stripped.png');
  assert.equal(after.exif.present, false);
  assert.equal(after.metadataText.length, 0);
  assert.equal(after.image.width, 1);
});

test('standalone TIFF files are parsed through the same TIFF reader', () => {
  const result = analyzeFile(buildTiff(), 'scan.tiff');
  assert.equal(result.file.format, 'tiff');
  assert.equal(result.exif.present, true);
  assert.equal(result.exif.gps.latitude, 12.9716);
  assert.equal(result.stripSupported, false);
});

test('stripMetadata refuses unsupported formats without touching data', () => {
  const gif = Buffer.from('GIF89a------');
  const stripped = stripMetadata(gif, 'anim.gif');
  assert.equal(stripped.ok, false);
  assert.match(stripped.error, /JPEG and PNG only/);
  assert.equal(stripped.buffer, undefined);
});

test('malformed TIFF headers fail safely', () => {
  assert.throws(() => parseTiff(Buffer.from('not-a-tiff')), /TIFF header/);
  assert.throws(
    () => parseTiff(Buffer.from([0x49, 0x49, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00])),
    /magic/,
  );
});

test('HEIC and PDF inputs are labelled as limited rather than misinterpreted', () => {
  const heic = Buffer.concat([
    Buffer.from([0x00, 0x00, 0x00, 0x18]),
    Buffer.from('ftypheic', 'latin1'),
    Buffer.alloc(16),
  ]);
  const heicResult = analyzeFile(heic, 'photo.heic');
  assert.equal(heicResult.file.format, 'heic');
  assert.equal(heicResult.stripSupported, false);
  assert.ok(heicResult.notes.some((note) => /HEIC/i.test(note)));

  const pdfResult = analyzeFile(Buffer.from('%PDF-1.7\n1 0 obj\n'), 'doc.pdf');
  assert.equal(pdfResult.file.format, 'pdf');
  assert.equal(pdfResult.file.mime, 'application/pdf');
  assert.ok(pdfResult.notes.some((note) => /PDF/i.test(note)));
});
