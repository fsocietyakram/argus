import { inflateSync } from 'node:zlib';
import { basename, extname } from 'node:path';
import { md5, sha1, sha256, uniq, formatBytes, truncate } from './util.mjs';

/* ------------------------------------------------------------------ */
/* Constants                                                           */
/* ------------------------------------------------------------------ */

const TYPE_SIZES = { 1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 6: 1, 7: 1, 8: 2, 9: 4, 10: 8, 11: 4, 12: 8, 13: 4 };

const ORIENTATION = {
  1: 'Normal',
  2: 'Mirrored horizontally',
  3: 'Rotated 180°',
  4: 'Mirrored vertically',
  5: 'Mirrored horizontally, rotated 270°',
  6: 'Rotated 90° clockwise',
  7: 'Mirrored horizontally, rotated 90°',
  8: 'Rotated 270° clockwise',
};

const RESOLUTION_UNIT = { 1: 'None', 2: 'inches', 3: 'centimeters' };
const EXPOSURE_PROGRAM = {
  0: 'Not defined',
  1: 'Manual',
  2: 'Normal program',
  3: 'Aperture priority',
  4: 'Shutter priority',
  5: 'Creative program',
  6: 'Action program',
  7: 'Portrait mode',
  8: 'Landscape mode',
};
const METERING_MODE = {
  0: 'Unknown',
  1: 'Average',
  2: 'Center-weighted average',
  3: 'Spot',
  4: 'Multi-spot',
  5: 'Pattern',
  6: 'Partial',
  255: 'Other',
};
const COLOR_SPACE = { 1: 'sRGB', 2: 'Adobe RGB', 65535: 'Uncalibrated' };
const FLASH = {
  0x0: 'No flash',
  0x1: 'Fired',
  0x5: 'Fired, return light not detected',
  0x7: 'Fired, return light detected',
  0x9: 'Fired, compulsory',
  0xd: 'Fired, compulsory, return light not detected',
  0xf: 'Fired, compulsory, return light detected',
  0x10: 'Did not fire, compulsory',
  0x18: 'Did not fire, auto',
  0x19: 'Fired, auto',
  0x1d: 'Fired, auto, return light not detected',
  0x1f: 'Fired, auto, return light detected',
  0x20: 'No flash function',
  0x41: 'Fired, red-eye reduction',
  0x45: 'Fired, red-eye reduction, return light not detected',
  0x47: 'Fired, red-eye reduction, return light detected',
  0x49: 'Fired, compulsory, red-eye reduction',
  0x4d: 'Fired, compulsory, red-eye reduction, return light not detected',
  0x4f: 'Fired, compulsory, red-eye reduction, return light detected',
  0x59: 'Fired, auto, red-eye reduction',
};

const IFD0_TAGS = {
  0x0100: 'ImageWidth',
  0x0101: 'ImageLength',
  0x010e: 'ImageDescription',
  0x010f: 'Make',
  0x0110: 'Model',
  0x0112: 'Orientation',
  0x011a: 'XResolution',
  0x011b: 'YResolution',
  0x0128: 'ResolutionUnit',
  0x0131: 'Software',
  0x0132: 'DateTime',
  0x013b: 'Artist',
  0x013c: 'HostComputer',
  0x013e: 'WhitePoint',
  0x013f: 'PrimaryChromaticities',
  0x0211: 'YCbCrCoefficients',
  0x0213: 'YCbCrPositioning',
  0x0214: 'ReferenceBlackWhite',
  0x8298: 'Copyright',
  0x8769: 'ExifIFDPointer',
  0x8825: 'GPSInfoIFDPointer',
  0x9c9b: 'XPTitle',
  0x9c9c: 'XPComment',
  0x9c9d: 'XPAuthor',
  0x9c9e: 'XPKeywords',
  0x9c9f: 'XPSubject',
  0xc4a5: 'PrintImageMatching',
  0x0201: 'JPEGInterchangeFormat',
  0x0202: 'JPEGInterchangeFormatLength',
};

const EXIF_TAGS = {
  0x829a: 'ExposureTime',
  0x829d: 'FNumber',
  0x8822: 'ExposureProgram',
  0x8824: 'SpectralSensitivity',
  0x8827: 'ISOSpeedRatings',
  0x8828: 'OECF',
  0x8830: 'SensitivityType',
  0x8832: 'RecommendedExposureIndex',
  0x9000: 'ExifVersion',
  0x9003: 'DateTimeOriginal',
  0x9004: 'DateTimeDigitized',
  0x9010: 'OffsetTime',
  0x9011: 'OffsetTimeOriginal',
  0x9012: 'OffsetTimeDigitized',
  0x9101: 'ComponentsConfiguration',
  0x9102: 'CompressedBitsPerPixel',
  0x9201: 'ShutterSpeedValue',
  0x9202: 'ApertureValue',
  0x9203: 'BrightnessValue',
  0x9204: 'ExposureBiasValue',
  0x9205: 'MaxApertureValue',
  0x9206: 'SubjectDistance',
  0x9207: 'MeteringMode',
  0x9208: 'LightSource',
  0x9209: 'Flash',
  0x920a: 'FocalLength',
  0x9214: 'SubjectArea',
  0x927c: 'MakerNote',
  0x9286: 'UserComment',
  0x9290: 'SubSecTime',
  0x9291: 'SubSecTimeOriginal',
  0x9292: 'SubSecTimeDigitized',
  0xa000: 'FlashpixVersion',
  0xa001: 'ColorSpace',
  0xa002: 'PixelXDimension',
  0xa003: 'PixelYDimension',
  0xa004: 'RelatedSoundFile',
  0xa005: 'InteroperabilityIFDPointer',
  0xa20b: 'FlashEnergy',
  0xa20e: 'FocalPlaneXResolution',
  0xa20f: 'FocalPlaneYResolution',
  0xa210: 'FocalPlaneResolutionUnit',
  0xa214: 'SubjectLocation',
  0xa215: 'ExposureIndex',
  0xa217: 'SensingMethod',
  0xa300: 'FileSource',
  0xa301: 'SceneType',
  0xa302: 'CFAPattern',
  0xa401: 'CustomRendered',
  0xa402: 'ExposureMode',
  0xa403: 'WhiteBalance',
  0xa404: 'DigitalZoomRatio',
  0xa405: 'FocalLengthIn35mmFilm',
  0xa406: 'SceneCaptureType',
  0xa407: 'GainControl',
  0xa408: 'Contrast',
  0xa409: 'Saturation',
  0xa40a: 'Sharpness',
  0xa40b: 'DeviceSettingDescription',
  0xa40c: 'SubjectDistanceRange',
  0xa420: 'ImageUniqueID',
  0xa430: 'CameraOwnerName',
  0xa431: 'BodySerialNumber',
  0xa432: 'LensSpecification',
  0xa433: 'LensMake',
  0xa434: 'LensModel',
  0xa435: 'LensSerialNumber',
  0xa460: 'CompositeImage',
  0xa461: 'SourceImageNumberOfCompositeImage',
  0xa462: 'SourceExposureTimesOfCompositeImage',
  0xa500: 'Gamma',
};

const GPS_TAGS = {
  0x0000: 'GPSVersionID',
  0x0001: 'GPSLatitudeRef',
  0x0002: 'GPSLatitude',
  0x0003: 'GPSLongitudeRef',
  0x0004: 'GPSLongitude',
  0x0005: 'GPSAltitudeRef',
  0x0006: 'GPSAltitude',
  0x0007: 'GPSTimeStamp',
  0x0008: 'GPSSatellites',
  0x0009: 'GPSStatus',
  0x000a: 'GPSMeasureMode',
  0x000b: 'GPSDOP',
  0x000c: 'GPSSpeedRef',
  0x000d: 'GPSSpeed',
  0x000e: 'GPSTrackRef',
  0x000f: 'GPSTrack',
  0x0010: 'GPSImgDirectionRef',
  0x0011: 'GPSImgDirection',
  0x0012: 'GPSMapDatum',
  0x0013: 'GPSDestLatitudeRef',
  0x0014: 'GPSDestLatitude',
  0x0015: 'GPSDestLongitudeRef',
  0x0016: 'GPSDestLongitude',
  0x0017: 'GPSDestBearingRef',
  0x0018: 'GPSDestBearing',
  0x0019: 'GPSDestDistanceRef',
  0x001a: 'GPSDestDistance',
  0x001b: 'GPSProcessingMethod',
  0x001c: 'GPSAreaInformation',
  0x001d: 'GPSDateStamp',
  0x001e: 'GPSDifferential',
  0x001f: 'GPSHPositioningError',
};

const INTEROP_TAGS = {
  0x0001: 'InteroperabilityIndex',
  0x0002: 'InteroperabilityVersion',
  0x1000: 'RelatedImageFileFormat',
  0x1001: 'RelatedImageWidth',
  0x1002: 'RelatedImageLength',
};

const XP_TAGS = new Set([0x9c9b, 0x9c9c, 0x9c9d, 0x9c9e, 0x9c9f]);
const POINTER_TAGS = new Set([0x8769, 0x8825, 0xa005]);
const HIDDEN_TAGS = new Set([0x0201, 0x0202, 0x927c]);

const MIME_BY_FORMAT = {
  jpeg: 'image/jpeg',
  png: 'image/png',
  webp: 'image/webp',
  gif: 'image/gif',
  tiff: 'image/tiff',
  heic: 'image/heic',
  pdf: 'application/pdf',
  unknown: 'application/octet-stream',
};

/* ------------------------------------------------------------------ */
/* Bounds-checked TIFF/EXIF parsing                                    */
/* ------------------------------------------------------------------ */

function need(buf, offset, length) {
  if (!Number.isInteger(offset) || offset < 0 || offset + length > buf.length) {
    throw new Error('Metadata offset points outside the file.');
  }
}

const u16 = (buf, offset, little) => {
  need(buf, offset, 2);
  return little ? buf.readUInt16LE(offset) : buf.readUInt16BE(offset);
};
const u32 = (buf, offset, little) => {
  need(buf, offset, 4);
  return little ? buf.readUInt32LE(offset) : buf.readUInt32BE(offset);
};

function readTagValue(buf, offset, type, count, little, tag) {
  const total = TYPE_SIZES[type] * count;
  if (!Number.isFinite(total) || total < 0 || total > 4_000_000) {
    throw new Error('Metadata value is unreasonably large.');
  }
  need(buf, offset, total);

  if (XP_TAGS.has(tag)) return Buffer.from(buf.subarray(offset, offset + total));

  switch (type) {
    case 1: {
      const values = Array.from(buf.subarray(offset, offset + count));
      return count === 1 ? values[0] : values;
    }
    case 2: {
      const text = buf.subarray(offset, offset + count).toString('latin1');
      return text.replace(/\0+$/g, '').replace(/\0/g, ' ').trim();
    }
    case 3: {
      const values = [];
      for (let i = 0; i < count; i++) values.push(buf.readUInt16LE(offset + i * 2));
      return count === 1 ? values[0] : values;
    }
    case 4: {
      const values = [];
      for (let i = 0; i < count; i++) {
        values.push(little ? buf.readUInt32LE(offset + i * 4) : buf.readUInt32BE(offset + i * 4));
      }
      return count === 1 ? values[0] : values;
    }
    case 5:
    case 10: {
      const values = [];
      for (let i = 0; i < count; i++) {
        const base = offset + i * 8;
        const numerator = little ? buf.readUInt32LE(base) : buf.readUInt32BE(base);
        const denominator = little ? buf.readUInt32LE(base + 4) : buf.readUInt32BE(base + 4);
        values.push(denominator === 0 ? 0 : numerator / denominator);
      }
      return count === 1 ? values[0] : values;
    }
    case 6: {
      const values = [];
      for (let i = 0; i < count; i++) values.push(buf.readInt8(offset + i));
      return count === 1 ? values[0] : values;
    }
    case 7:
      return Buffer.from(buf.subarray(offset, offset + total));
    case 8: {
      const values = [];
      for (let i = 0; i < count; i++) {
        values.push(little ? buf.readInt16LE(offset + i * 2) : buf.readInt16BE(offset + i * 2));
      }
      return count === 1 ? values[0] : values;
    }
    case 9: {
      const values = [];
      for (let i = 0; i < count; i++) {
        values.push(little ? buf.readInt32LE(offset + i * 4) : buf.readInt32BE(offset + i * 4));
      }
      return count === 1 ? values[0] : values;
    }
    case 11: {
      const values = [];
      for (let i = 0; i < count; i++) {
        values.push(little ? buf.readFloatLE(offset + i * 4) : buf.readFloatBE(offset + i * 4));
      }
      return count === 1 ? values[0] : values;
    }
    case 12: {
      const values = [];
      for (let i = 0; i < count; i++) {
        values.push(little ? buf.readDoubleLE(offset + i * 8) : buf.readDoubleBE(offset + i * 8));
      }
      return count === 1 ? values[0] : values;
    }
    case 13: {
      const values = [];
      for (let i = 0; i < count; i++) {
        values.push(little ? buf.readUInt32LE(offset + i * 4) : buf.readUInt32BE(offset + i * 4));
      }
      return count === 1 ? values[0] : values;
    }
    default:
      return Buffer.from(buf.subarray(offset, offset + Math.min(total, 64)));
  }
}

function decodeUserComment(buffer) {
  if (!Buffer.isBuffer(buffer) || buffer.length === 0) return '';
  const head = buffer.subarray(0, 8).toString('latin1');
  const body = buffer.subarray(8);
  if (head.startsWith('ASCII')) return body.toString('latin1').replace(/\0+$/g, '').trim();
  if (head.startsWith('UNICODE')) {
    try {
      return new TextDecoder('utf-16be').decode(body).replace(/\0+$/g, '').trim();
    } catch {
      return body.toString('utf16le').replace(/\0+$/g, '').trim();
    }
  }
  if (head.startsWith('JIS')) return '[JIS-encoded comment]';
  return buffer.toString('latin1').replace(/\0+$/g, '').trim();
}

const num = (value) => {
  if (typeof value !== 'number' || !Number.isFinite(value)) return String(value);
  return Number.isInteger(value) ? String(value) : String(Math.round(value * 1000) / 1000);
};

const pad2 = (value) => String(Math.trunc(Number(value))).padStart(2, '0');

function formatTagValue(group, tag, value, type) {
  if (Buffer.isBuffer(value)) {
    if (tag === 0x9286) return decodeUserComment(value);
    if (tag === 0x9000 || tag === 0xa000) return value.toString('latin1').replace(/\0+$/g, '');
    if (XP_TAGS.has(tag)) return value.toString('utf16le').replace(/\0+$/g, '').trim();
    if (tag === 0x0000) return Array.from(value).join('.');
    return `[${value.length} bytes] ${value.subarray(0, 32).toString('hex')}${value.length > 32 ? '…' : ''}`;
  }

  if (tag === 0x0112) return ORIENTATION[value] || String(value);
  if (tag === 0x0128 || tag === 0xa210) return RESOLUTION_UNIT[value] || String(value);
  if (tag === 0x8822) return EXPOSURE_PROGRAM[value] || String(value);
  if (tag === 0x9207) return METERING_MODE[value] || String(value);
  if (tag === 0xa001) return COLOR_SPACE[value] || String(value);
  if (tag === 0x9209) return FLASH[value] || String(value);
  if (tag === 0x920a) return typeof value === 'number' ? `${num(value)} mm` : String(value);
  if (tag === 0xa405) return typeof value === 'number' ? `${num(value)} mm (35 mm equivalent)` : String(value);
  if (tag === 0x829a && typeof value === 'number') {
    return value > 0 && value < 1 ? `1/${Math.round(1 / value)} s` : `${num(value)} s`;
  }
  if ((tag === 0x829d || tag === 0x9202 || tag === 0x9205) && typeof value === 'number') {
    return `f/${num(value)}`;
  }
  if ([0x0132, 0x9003, 0x9004].includes(tag)) {
    return String(value).replace(/^(\d{4}):(\d{2}):(\d{2})/, '$1-$2-$3');
  }
  if (tag === 0x9010 || tag === 0x9011 || tag === 0x9012) return String(value);
  if (group === 'GPS' && (tag === 0x0002 || tag === 0x0004 || tag === 0x0014 || tag === 0x0016)) {
    if (Array.isArray(value) && value.length >= 3) {
      return `${num(value[0])}° ${num(value[1])}' ${num(value[2])}"`;
    }
    return String(value);
  }
  if (group === 'GPS' && tag === 0x0007 && Array.isArray(value) && value.length >= 3) {
    return `${pad2(value[0])}:${pad2(value[1])}:${pad2(value[2])} UTC`;
  }
  if (group === 'GPS' && tag === 0x0005) return Number(value) === 1 ? 'Below sea level' : 'Above sea level';
  if (group === 'GPS' && tag === 0x001d) return String(value).replaceAll(':', '-');
  if (group === 'GPS' && (tag === 0x0006 || tag === 0x000b || tag === 0x001a || tag === 0x001f)) {
    return typeof value === 'number' ? `${num(value)} m` : String(value);
  }
  if (tag === 0x9101 && Array.isArray(value)) {
    const map = { 0: '-', 1: 'Y', 2: 'Cb', 3: 'Cr', 4: 'R', 5: 'G', 6: 'B' };
    return value.map((v) => map[v] || v).join('');
  }
  if (tag === 0xa432 && Array.isArray(value) && value.length === 4) {
    return `${num(value[0])}-${num(value[1])} mm, f/${num(value[2])}-${num(value[3])}`;
  }
  if (tag === 0xa300) return value === 3 ? 'Digital still camera' : String(value);
  if (tag === 0xa301) return value === 1 ? 'Directly photographed' : String(value);

  if (Array.isArray(value)) {
    if (value.length > 16) return `${value.slice(0, 16).map(num).join(', ')} … (${value.length} values)`;
    return value.map(num).join(', ');
  }
  if (typeof value === 'object' && value !== null) return JSON.stringify(value);
  return String(value);
}

function parseIfd(buf, base, dirOffset, group, out, depth, visited) {
  const little = out.littleEndian;
  if (depth > 4) return;
  if (visited.has(dirOffset)) return;
  visited.add(dirOffset);

  const count = u16(buf, dirOffset, little);
  if (count > 512) throw new Error(`Unreasonable IFD entry count (${count}).`);

  const entries = [];
  const rawValues = {};

  for (let index = 0; index < count; index++) {
    const entryOffset = dirOffset + 2 + index * 12;
    need(buf, entryOffset, 12);
    const tag = u16(buf, entryOffset, little);
    const type = u16(buf, entryOffset + 2, little);
    const valueCount = u32(buf, entryOffset + 4, little);
    const typeSize = TYPE_SIZES[type];
    if (!typeSize) continue;

    const byteLength = typeSize * valueCount;
    if (!Number.isFinite(byteLength) || byteLength < 0 || byteLength > 4_000_000) continue;

    // Pointer tags are handled recursively; their 4-byte field is an offset.
    if (POINTER_TAGS.has(tag)) {
      const pointer = u32(buf, entryOffset + 8, little);
      if (pointer > 0 && pointer < buf.length) {
        const childGroup = tag === 0x8769 ? 'Exif' : tag === 0x8825 ? 'GPS' : 'Interop';
        try {
          parseIfd(buf, base, base + pointer, childGroup, out, depth + 1, visited);
        } catch (err) {
          out.warnings.push(`${childGroup} metadata: ${err.message}`);
        }
      }
      continue;
    }

    const valueOffset = byteLength <= 4 ? entryOffset + 8 : base + u32(buf, entryOffset + 8, little);
    need(buf, valueOffset, byteLength);

    if (tag === 0x927c) {
      entries.push({
        tag: `0x${tag.toString(16).padStart(4, '0')}`,
        name: 'MakerNote',
        value: `[vendor maker note, ${byteLength} bytes — not interpreted]`,
      });
      continue;
    }

    let value;
    try {
      value = readTagValue(buf, valueOffset, type, valueCount, little, tag);
    } catch (err) {
      out.warnings.push(`Tag 0x${tag.toString(16)}: ${err.message}`);
      continue;
    }

    rawValues[tag] = value;
    entries.push({
      tag: `0x${tag.toString(16).padStart(4, '0')}`,
      name:
        (group === 'IFD0' || group === 'IFD1' ? IFD0_TAGS : group === 'Exif' ? EXIF_TAGS : group === 'GPS' ? GPS_TAGS : INTEROP_TAGS)[tag] ||
        `Unknown (0x${tag.toString(16)})`,
      value: formatTagValue(group, tag, value, type),
    });
  }

  if (entries.length) out.ifds[group] = entries;
  out.raw[group] = rawValues;

  // Thumbnail IFD
  const nextOffsetPosition = dirOffset + 2 + count * 12;
  const nextOffset = u32(buf, nextOffsetPosition, little);
  if (group === 'IFD0' && nextOffset > 0 && nextOffset < buf.length) {
    out.hasThumbnail = true;
    try {
      parseIfd(buf, base, base + nextOffset, 'IFD1', out, depth + 1, visited);
    } catch (err) {
      out.warnings.push(`Thumbnail metadata: ${err.message}`);
    }
  }
}

function gpsDecimal(values, ref) {
  if (!Array.isArray(values) || values.length < 3) return null;
  const [degrees, minutes, seconds] = values.map(Number);
  if (![degrees, minutes, seconds].every(Number.isFinite)) return null;
  let decimal = degrees + minutes / 60 + seconds / 3600;
  const direction = String(ref || '').trim().toUpperCase();
  if (direction === 'S' || direction === 'W') decimal = -decimal;
  return Math.round(decimal * 1e7) / 1e7;
}

function buildGps(rawGroups) {
  const gps = rawGroups.GPS || {};
  const lat = gpsDecimal(gps[0x0002], gps[0x0001]);
  const lon = gpsDecimal(gps[0x0004], gps[0x0003]);
  if (lat == null || lon == null) return null;
  if (Math.abs(lat) > 90 || Math.abs(lon) > 180) return null;

  const altitude = typeof gps[0x0006] === 'number' ? gps[0x0006] : null;
  const altitudeRef = Array.isArray(gps[0x0005]) ? gps[0x0005][0] : gps[0x0005];
  const belowSeaLevel = altitudeRef === 1;

  const latRef = String(gps[0x0001] || (lat >= 0 ? 'N' : 'S')).replace(/\0/g, '').trim() || (lat >= 0 ? 'N' : 'S');
  const lonRef = String(gps[0x0003] || (lon >= 0 ? 'E' : 'W')).replace(/\0/g, '').trim() || (lon >= 0 ? 'E' : 'W');

  const decimal = (value) => (Math.round(value * 1e6) / 1e6).toFixed(6);
  const coords = `${lat.toFixed(6)},${lon.toFixed(6)}`;

  return {
    latitude: lat,
    longitude: lon,
    latitudeRef: latRef,
    longitudeRef: lonRef,
    altitude: altitude == null ? null : belowSeaLevel ? -altitude : altitude,
    mapDatum: gps[0x0012] || null,
    timestamp: gps[0x0007] || null,
    dateStamp: gps[0x001d] || null,
    maps: {
      openstreetmap: `https://www.openstreetmap.org/?mlat=${decimal(lat)}&mlon=${decimal(lon)}#map=17/${decimal(lat)}/${decimal(lon)}`,
      google: `https://www.google.com/maps?q=${coords}`,
      geohack: `https://geohack.toolforge.org/geohack.php?params=${decimal(lat)};${decimal(lon)}`,
    },
  };
}

/**
 * Parse a TIFF/EXIF structure at `base` inside a JPEG/PNG/WebP/TIFF buffer.
 */
export function parseTiff(buf, base = 0) {
  need(buf, base, 8);
  const byteOrder = buf.subarray(base, base + 2).toString('latin1');
  if (byteOrder !== 'II' && byteOrder !== 'MM') {
    throw new Error('Not a TIFF header (expected II or MM).');
  }
  const little = byteOrder === 'II';
  if (u16(buf, base + 2, little) !== 42) throw new Error('Invalid TIFF magic number.');

  const out = {
    byteOrder: little ? 'little-endian' : 'big-endian',
    littleEndian: little,
    ifds: {},
    raw: {},
    warnings: [],
    hasThumbnail: false,
  };

  const firstIfd = u32(buf, base + 4, little);
  if (firstIfd > 0) parseIfd(buf, base, base + firstIfd, 'IFD0', out, 0, new Set());
  out.gps = buildGps(out.raw);
  return out;
}

/* ------------------------------------------------------------------ */
/* Container parsing                                                   */
/* ------------------------------------------------------------------ */

function parseJpeg(buf) {
  const result = {
    format: 'jpeg',
    exif: null,
    dims: null,
    jfif: null,
    icc: false,
    iptc: false,
    comments: [],
    xmp: [],
    warnings: [],
  };

  let offset = 2;
  while (offset + 4 <= buf.length) {
    if (buf[offset] !== 0xff) {
      offset++;
      continue;
    }
    let marker = buf[offset + 1];
    if (marker === 0xff) {
      offset++;
      continue;
    }
    if (marker === 0xd8 || marker === 0x01 || (marker >= 0xd0 && marker <= 0xd7)) {
      offset += 2;
      continue;
    }
    if (marker === 0xd9) break;

    const length = buf.readUInt16BE(offset + 2);
    if (length < 2) break;
    const dataStart = offset + 4;
    const dataEnd = offset + 2 + length;
    if (dataEnd > buf.length) {
      result.warnings.push('JPEG segment extends beyond end of file.');
      break;
    }
    const data = buf.subarray(dataStart, dataEnd);

    if (marker === 0xe0 && data.subarray(0, 5).toString('latin1') === 'JFIF\0') {
      result.jfif = `${data[5]}.${data[6]}`;
    } else if (marker === 0xe1) {
      if (data.subarray(0, 6).toString('latin1') === 'Exif\0\0' && !result.exif) {
        try {
          result.exif = parseTiff(buf, dataStart + 6);
        } catch (err) {
          result.warnings.push(`EXIF parse failed: ${err.message}`);
        }
      } else if (data.toString('latin1').includes('http://ns.adobe.com/xap/1.0/')) {
        const nul = data.indexOf(0);
        const xml = data.subarray(nul + 1).toString('utf8');
        result.xmp.push(...extractXmp(xml));
      }
    } else if (marker === 0xe2 && data.toString('latin1').startsWith('ICC_PROFILE')) {
      result.icc = true;
    } else if (marker === 0xed && data.toString('latin1').includes('Photoshop 3.0')) {
      result.iptc = true;
    } else if (marker === 0xfe) {
      const comment = data.toString('latin1').replace(/\0+$/g, '').trim();
      if (comment) result.comments.push(comment);
    } else if (
      [0xc0, 0xc1, 0xc2, 0xc3, 0xc5, 0xc6, 0xc7, 0xc9, 0xca, 0xcb, 0xcd, 0xce, 0xcf].includes(marker)
    ) {
      result.dims = {
        width: buf.readUInt16BE(dataStart + 3),
        height: buf.readUInt16BE(dataStart + 1),
        components: data[5],
      };
    } else if (marker === 0xda) {
      break; // start of scan; image data follows
    }

    offset = dataEnd;
  }

  return result;
}

function parsePng(buf) {
  const result = {
    format: 'png',
    exif: null,
    dims: null,
    text: [],
    icc: false,
    warnings: [],
    xmp: [],
  };

  let offset = 8;
  while (offset + 12 <= buf.length) {
    const length = buf.readUInt32BE(offset);
    const type = buf.subarray(offset + 4, offset + 8).toString('latin1');
    const dataStart = offset + 8;
    const dataEnd = dataStart + length;
    if (dataEnd + 4 > buf.length) {
      result.warnings.push(`PNG chunk ${type} extends beyond end of file.`);
      break;
    }
    const data = buf.subarray(dataStart, dataEnd);

    if (type === 'IHDR') {
      result.dims = {
        width: buf.readUInt32BE(dataStart),
        height: buf.readUInt32BE(dataStart + 4),
        bitDepth: data[8],
        colorType: data[9],
        interlace: data[12],
      };
    } else if (type === 'eXIf') {
      try {
        result.exif = parseTiff(buf, dataStart);
      } catch (err) {
        result.warnings.push(`PNG eXIf parse failed: ${err.message}`);
      }
    } else if (type === 'tEXt') {
      const nul = data.indexOf(0);
      if (nul > 0) {
        result.text.push({
          key: data.subarray(0, nul).toString('latin1'),
          value: data.subarray(nul + 1).toString('latin1').trim(),
          source: 'PNG tEXt',
        });
      }
    } else if (type === 'iTXt') {
      const nul = data.indexOf(0);
      if (nul > 0) {
        const key = data.subarray(0, nul).toString('latin1');
        const compressed = data[nul + 1] === 1;
        let pos = nul + 3;
        const langEnd = data.indexOf(0, pos);
        const transEnd = data.indexOf(0, langEnd + 1);
        const text = data.subarray(transEnd + 1);
        try {
          const value = (compressed ? inflateSync(text) : text).toString('utf8').trim();
          result.text.push({ key, value, source: 'PNG iTXt' });
        } catch {
          result.warnings.push(`Could not decompress PNG iTXt "${key}".`);
        }
      }
    } else if (type === 'zTXt') {
      const nul = data.indexOf(0);
      if (nul > 0) {
        const key = data.subarray(0, nul).toString('latin1');
        try {
          const value = inflateSync(data.subarray(nul + 2)).toString('latin1').trim();
          result.text.push({ key, value, source: 'PNG zTXt' });
        } catch {
          result.warnings.push(`Could not decompress PNG zTXt "${key}".`);
        }
      }
    } else if (type === 'iCCP') {
      result.icc = true;
    } else if (type === 'IEND') {
      break;
    }

    offset = dataEnd + 4;
  }

  return result;
}

function parseWebp(buf) {
  const result = { format: 'webp', exif: null, dims: null, xmp: [], icc: false, warnings: [] };
  let offset = 12;

  while (offset + 8 <= buf.length) {
    const fourcc = buf.subarray(offset, offset + 4).toString('latin1');
    const size = buf.readUInt32LE(offset + 4);
    const dataStart = offset + 8;
    const dataEnd = dataStart + size;
    if (dataEnd > buf.length) {
      result.warnings.push(`WebP chunk ${fourcc} extends beyond end of file.`);
      break;
    }
    const data = buf.subarray(dataStart, dataEnd);

    if (fourcc === 'VP8X' && size >= 10) {
      result.dims = {
        width: 1 + (data[4] | (data[5] << 8) | (data[6] << 16)),
        height: 1 + (data[7] | (data[8] << 8) | (data[9] << 16)),
      };
    } else if (fourcc === 'VP8 ' && size >= 10) {
      if (data.subarray(3, 6).toString('hex') === '9d012a') {
        result.dims = {
          width: data.readUInt16LE(6) & 0x3fff,
          height: data.readUInt16LE(8) & 0x3fff,
        };
      }
    } else if (fourcc === 'VP8L' && size >= 5) {
      const bits = data.readUInt32LE(1);
      result.dims = {
        width: (bits & 0x3fff) + 1,
        height: ((bits >> 14) & 0x3fff) + 1,
      };
    } else if (fourcc === 'EXIF') {
      let start = 0;
      if (data.subarray(0, 6).toString('latin1') === 'Exif\0\0') start = 6;
      try {
        result.exif = parseTiff(buf, dataStart + start);
      } catch (err) {
        result.warnings.push(`WebP EXIF parse failed: ${err.message}`);
      }
    } else if (fourcc === 'XMP ') {
      result.xmp.push(...extractXmp(data.toString('utf8')));
    } else if (fourcc === 'ICCP') {
      result.icc = true;
    }

    offset = dataEnd + (size % 2);
  }

  return result;
}

function parseGif(buf) {
  return {
    format: 'gif',
    exif: null,
    dims: buf.length >= 10 ? { width: buf.readUInt16LE(6), height: buf.readUInt16LE(8) } : null,
    warnings: [],
    xmp: [],
  };
}

function extractXmp(xml) {
  const fields = [];
  const add = (key, value) => {
    if (value == null) return;
    const text = String(value).replace(/\s+/g, ' ').trim();
    if (text) fields.push({ key, value: text, source: 'XMP' });
  };

  const element = (name) => {
    const match = xml.match(new RegExp(`<${name}[^>]*>([\\s\\S]*?)</${name}>`, 'i'));
    if (!match) return undefined;
    return match[1].replace(/<[^>]+>/g, ' ').replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>').trim();
  };
  const attribute = (name) => {
    const match = xml.match(new RegExp(`\\b${name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}="([^"]*)"`, 'i'));
    return match?.[1];
  };

  add('Title', element('dc:title') ?? attribute('dc:title'));
  add('Creator', element('dc:creator') ?? attribute('dc:creator'));
  add('Description', element('dc:description') ?? attribute('dc:description'));
  add('Creator tool', element('xmp:CreatorTool') ?? attribute('xmp:CreatorTool'));
  add('Created', element('xmp:CreateDate') ?? attribute('xmp:CreateDate'));
  add('Modified', element('xmp:ModifyDate') ?? attribute('xmp:ModifyDate'));
  add('Metadata date', element('xmp:MetadataDate') ?? attribute('xmp:MetadataDate'));
  add('Document ID', element('xmpMM:DocumentID') ?? attribute('xmpMM:DocumentID'));
  add('Instance ID', element('xmpMM:InstanceID') ?? attribute('xmpMM:InstanceID'));
  add('Derived from', element('xmpMM:DerivedFrom') ?? attribute('xmpMM:DerivedFrom'));
  add('GPS latitude', element('exif:GPSLatitude') ?? attribute('exif:GPSLatitude'));
  add('GPS longitude', element('exif:GPSLongitude') ?? attribute('exif:GPSLongitude'));
  add('Software', element('photoshop:Software') ?? attribute('photoshop:Software'));

  return fields;
}

/* ------------------------------------------------------------------ */
/* Strings / derived intelligence                                      */
/* ------------------------------------------------------------------ */

function extractStrings(buf) {
  const text = buf.toString('latin1', 0, Math.min(buf.length, 8 * 1024 * 1024));
  const collect = (regex, map, limit = 25) => {
    const values = [];
    for (const match of text.matchAll(regex)) {
      const value = (typeof map === 'function' ? map(match) : match[0])?.trim();
      if (value) values.push(value);
      if (values.length >= limit * 3) break;
    }
    return uniq(values).slice(0, limit);
  };

  const emails = collect(/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g, (match) => match[0])
    .filter((email) => email.length < 80 && !email.endsWith('.png') && !email.endsWith('.jpg'));

  const urls = collect(/https?:\/\/[^\s"'<>\\)\]]{4,300}/g, (match) => match[0].replace(/[.,;]+$/, ''));

  const handles = collect(
    /(?:^|[\s"'>])@([A-Za-z0-9._]{2,30})\b/g,
    (match) => `@${match[1]}`,
    15,
  );

  const paths = collect(/[A-Za-z]:\\[^\x00-\x1f:*?"<>|]{3,120}/g, (match) => match[0], 15);
  const unixPaths = collect(/(?:\/Users|\/home)\/[A-Za-z0-9._-]+(?:\/[^\x00-\x1f"'<>]{0,80})?/g, (match) => match[0], 10);

  const ips = collect(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g, (match) => match[0], 15).filter((ip) =>
    ip.split('.').every((part) => Number(part) >= 0 && Number(part) <= 255),
  );

  return {
    emails,
    urls,
    handles,
    paths: [...paths, ...unixPaths].slice(0, 20),
    ips,
  };
}

/* ------------------------------------------------------------------ */
/* Public API                                                          */
/* ------------------------------------------------------------------ */

export function detectFormat(buf, filename = '') {
  if (buf.length >= 3 && buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff) return 'jpeg';
  if (buf.length >= 8 && buf.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]))) {
    return 'png';
  }
  if (
    buf.length >= 12 &&
    buf.subarray(0, 4).toString('latin1') === 'RIFF' &&
    buf.subarray(8, 12).toString('latin1') === 'WEBP'
  ) {
    return 'webp';
  }
  if (buf.length >= 6 && ['GIF87a', 'GIF89a'].includes(buf.subarray(0, 6).toString('latin1'))) {
    return 'gif';
  }
  if (buf.length >= 4) {
    const head = buf.subarray(0, 4).toString('latin1');
    if (head === 'II*\0' || head === 'MM\0*') return 'tiff';
  }
  if (buf.length >= 12 && buf.subarray(4, 8).toString('latin1') === 'ftyp') {
    const brand = buf.subarray(8, 12).toString('latin1').toLowerCase();
    if (['heic', 'heix', 'hevc', 'hevx', 'mif1', 'msf1'].includes(brand)) return 'heic';
  }
  if (buf.length >= 5 && buf.subarray(0, 5).toString('latin1') === '%PDF-') return 'pdf';
  if (filename && extname(filename)) {
    const ext = extname(filename).slice(1).toLowerCase();
    if (['jpg', 'jpeg'].includes(ext)) return 'jpeg';
    if (ext === 'png') return 'png';
    if (ext === 'webp') return 'webp';
    if (ext === 'gif') return 'gif';
    if (['tif', 'tiff'].includes(ext)) return 'tiff';
    if (['heic', 'heif'].includes(ext)) return 'heic';
    if (ext === 'pdf') return 'pdf';
  }
  return 'unknown';
}

/**
 * Analyse a file the operator is authorised to examine.
 * Returns a JSON-serialisable forensic report. Never writes the file anywhere.
 */
export function analyzeFile(buffer, filename = 'file') {
  const started = Date.now();
  const format = detectFormat(buffer, filename);
  const container = { format, exif: null, dims: null, warnings: [], xmp: [], text: [], comments: [], icc: false, iptc: false, jfif: null };

  try {
    if (format === 'jpeg') Object.assign(container, parseJpeg(buffer));
    else if (format === 'png') Object.assign(container, parsePng(buffer));
    else if (format === 'webp') Object.assign(container, parseWebp(buffer));
    else if (format === 'gif') Object.assign(container, parseGif(buffer));
    else if (format === 'tiff') {
      container.exif = parseTiff(buffer, 0);
      container.dims = null;
    }
  } catch (err) {
    container.warnings.push(`Container parse failed: ${err.message}`);
  }

  const exif = container.exif;
  const groups = exif?.ifds || {};
  const gps = exif?.gps || null;
  const warnings = uniq([...(container.warnings || []), ...(exif?.warnings || [])]).filter(Boolean);

  const metadataText = [
    ...(container.text || []),
    ...(container.xmp || []),
    ...(container.comments || []).map((value, index) => ({
      key: `JPEG comment ${index + 1}`,
      value,
      source: 'JPEG COM',
    })),
  ].filter((entry) => entry.value);

  const strings = extractStrings(buffer);

  const find = (groupName, tag) => {
    const hex = `0x${tag.toString(16).padStart(4, '0')}`;
    const displayed = groups[groupName]?.find((entry) => entry.tag === hex);
    if (displayed) return displayed.value || null;
    const raw = exif?.raw?.[groupName]?.[tag];
    if (raw == null) return null;
    if (Buffer.isBuffer(raw)) return raw.toString('latin1').replace(/\0+$/g, '').trim() || null;
    if (Array.isArray(raw)) return raw.length ? raw.map(num).join(', ') : null;
    return String(raw);
  };

  const camera = {
    make: find('IFD0', 0x010f),
    model: find('IFD0', 0x0110),
    lensMake: find('Exif', 0xa433),
    lensModel: find('Exif', 0xa434),
    serialNumber: find('Exif', 0xa431),
    lensSerialNumber: find('Exif', 0xa435),
    ownerName: find('Exif', 0xa430),
    software: find('IFD0', 0x0131),
    artist: find('IFD0', 0x013b),
    copyright: find('IFD0', 0x8298),
    hostComputer: find('IFD0', 0x013c),
    imageDescription: find('IFD0', 0x010e),
  };

  const userComment = find('Exif', 0x9286);
  const takenAt = find('Exif', 0x9003);
  const digitizedAt = find('Exif', 0x9004);
  const modifiedAt = find('IFD0', 0x0132);
  const uniqueId = find('Exif', 0xa420);

  const gpsPresent = Boolean(gps && Number.isFinite(gps.latitude));

  const dims = container.dims || (groups.IFD0
    ? {
        width: exif.raw?.IFD0?.[0x0100] ?? null,
        height: exif.raw?.IFD0?.[0x0101] ?? null,
      }
    : null);

  const riskFindings = [];
  let riskScore = 0;
  const addRisk = (points, text) => {
    riskScore += points;
    riskFindings.push({ points, text });
  };

  if (gpsPresent) addRisk(45, `GPS coordinates are embedded (${gps.latitude}, ${gps.longitude}).`);
  if (camera.make || camera.model) {
    addRisk(10, `Camera identity is embedded${camera.make ? ` (${camera.make}` : ' ('}${camera.model ? ` ${camera.model})` : ')'}.`);
  }
  if (camera.serialNumber || camera.lensSerialNumber || camera.ownerName) {
    addRisk(20, 'Device serial number or camera owner name is embedded.');
  }
  if (camera.software) addRisk(5, `Editing software is recorded (${truncate(camera.software, 60)}).`);
  if (metadataText.some((entry) => /creator tool|software|document id/i.test(entry.key))) {
    addRisk(5, 'Creator software or document identifier is present in non-EXIF metadata.');
  }
  if (takenAt || digitizedAt || modifiedAt) addRisk(10, 'Original capture or modification timestamps are embedded.');
  if (camera.artist || camera.copyright || camera.imageDescription) {
    addRisk(10, 'Author, copyright, or description fields are populated.');
  }
  if (userComment) addRisk(10, 'A user comment is embedded in the EXIF data.');
  if (uniqueId) addRisk(5, 'An EXIF ImageUniqueID is present.');
  if (strings.emails.length || strings.urls.length || strings.handles.length) {
    addRisk(10, 'Plain-text contact details or URLs were found in the file bytes.');
  }

  riskScore = Math.min(100, riskScore);
  const riskLevel = riskScore >= 60 ? 'high' : riskScore >= 30 ? 'medium' : riskScore > 0 ? 'low' : 'none';

  const notes = [
    'All values were read directly from the supplied file in memory; the original was not uploaded, modified, or retained by the server.',
    'EXIF timestamps usually have no timezone. Treat them as local device time unless an offset tag is present.',
    'Maker notes are vendor-specific and are not interpreted.',
    'Presence of metadata is not proof of authorship; metadata can be edited or copied.',
  ];

  if (!exif) notes.push('No EXIF block was found in this file.');
  if (format === 'heic') notes.push('HEIC/HEIF containers are detected but not deeply parsed yet; only strings are extracted.');
  if (format === 'pdf') notes.push('PDF parsing is limited to plain-text strings in this version.');

  return {
    schema: 'argus.report/v1',
    command: 'file',
    tool: { name: 'ARGUS', version: '1.0.0' },
    target: basename(filename || 'file'),
    createdAt: new Date().toISOString(),
    durationMs: Date.now() - started,
    file: {
      name: basename(filename || 'file'),
      size: buffer.length,
      sizeHuman: formatBytes(buffer.length),
      format,
      mime: MIME_BY_FORMAT[format] || MIME_BY_FORMAT.unknown,
      sha256: sha256(buffer),
      sha1: sha1(buffer),
      md5: md5(buffer),
    },
    image: {
      format,
      width: dims?.width ?? null,
      height: dims?.height ?? null,
      bitDepth: dims?.bitDepth ?? null,
      colorType: dims?.colorType ?? null,
      jfif: container.jfif || null,
      hasIccProfile: Boolean(container.icc),
      hasIptc: Boolean(container.iptc),
      hasThumbnail: Boolean(exif?.hasThumbnail),
    },
    exif: {
      present: Boolean(exif),
      byteOrder: exif?.byteOrder || null,
      groups,
      tagCount: Object.values(groups).reduce((total, entries) => total + entries.length, 0),
      gps,
      camera,
      timestamps: {
        original: takenAt,
        digitized: digitizedAt,
        modified: modifiedAt,
      },
      userComment,
      uniqueId,
    },
    metadataText,
    strings,
    risk: {
      score: riskScore,
      level: riskLevel,
      findings: riskFindings,
      recommendations: [
        'Share a metadata-stripped copy unless the metadata is evidence you need to preserve.',
        'Preserve the original separately if it may be needed for evidentiary purposes.',
      ],
    },
    stripSupported: format === 'jpeg' || format === 'png',
    warnings,
    notes,
  };
}

/* ------------------------------------------------------------------ */
/* Metadata stripping (works on a copy)                                */
/* ------------------------------------------------------------------ */

export function stripMetadata(buffer, filename = 'file') {
  const format = detectFormat(buffer, filename);
  const removed = [];

  if (format === 'jpeg') {
    const parts = [buffer.subarray(0, 2)];
    let offset = 2;
    let sawEoi = false;

    while (offset + 4 <= buffer.length) {
      if (buffer[offset] !== 0xff) break;
      const marker = buffer[offset + 1];
      if (marker === 0xff) {
        offset++;
        continue;
      }
      if (marker === 0xda) {
        parts.push(buffer.subarray(offset));
        offset = buffer.length;
        break;
      }
      if (marker === 0xd9) {
        parts.push(buffer.subarray(offset, offset + 2));
        offset += 2;
        sawEoi = true;
        break;
      }
      if (marker >= 0xd0 && marker <= 0xd7) {
        parts.push(buffer.subarray(offset, offset + 2));
        offset += 2;
        continue;
      }

      const length = buffer.readUInt16BE(offset + 2);
      if (length < 2) break;
      const end = offset + 2 + length;
      if (end > buffer.length) break;
      const data = buffer.subarray(offset + 4, end);
      const prefix = data.subarray(0, 32).toString('latin1');

      const isExif = marker === 0xe1 && prefix.startsWith('Exif\0\0');
      const isXmp = marker === 0xe1 && prefix.includes('http://ns.adobe.com/xap/1.0/');
      const isIptc = marker === 0xed && prefix.includes('Photoshop 3.0');
      const isComment = marker === 0xfe;

      if (isExif) removed.push('EXIF (APP1)');
      else if (isXmp) removed.push('XMP (APP1)');
      else if (isIptc) removed.push('IPTC / Photoshop (APP13)');
      else if (isComment) removed.push('JPEG comment (COM)');

      if (!isExif && !isXmp && !isIptc && !isComment) {
        parts.push(buffer.subarray(offset, end));
      }
      offset = end;
    }

    if (offset < buffer.length) parts.push(buffer.subarray(offset));
    const output = Buffer.concat(parts);
    return {
      ok: true,
      format,
      buffer: output,
      removed: uniq(removed),
      note: sawEoi
        ? 'Removed metadata and saved a copy.'
        : 'Removed metadata and saved a copy; verify the copy opens correctly.',
    };
  }

  if (format === 'png') {
    const parts = [buffer.subarray(0, 8)];
    let offset = 8;
    while (offset + 12 <= buffer.length) {
      const length = buffer.readUInt32BE(offset);
      const type = buffer.subarray(offset + 4, offset + 8).toString('latin1');
      const end = offset + 12 + length;
      if (end > buffer.length) break;
      if (['eXIf', 'tEXt', 'zTXt', 'iTXt', 'tIME'].includes(type)) {
        removed.push(`PNG ${type}`);
      } else {
        parts.push(buffer.subarray(offset, end));
      }
      if (type === 'IEND') break;
      offset = end;
    }
    return {
      ok: true,
      format,
      buffer: Buffer.concat(parts),
      removed: uniq(removed),
      note: 'Removed metadata chunks and saved a copy.',
    };
  }

  return {
    ok: false,
    format,
    error: `Metadata stripping is supported for JPEG and PNG only (received ${format}).`,
  };
}
