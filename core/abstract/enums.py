HWPTAG_BEGIN = 0x10
tag_table = {
    HWPTAG_BEGIN: 'HWPTAG_DOCUMENT_PROPERTIES',
    HWPTAG_BEGIN + 1: 'HWPTAG_ID_MAPPINGS',
    HWPTAG_BEGIN + 2: 'HWPTAG_BIN_DATA',
    HWPTAG_BEGIN + 3: 'HWPTAG_FACE_NAME',
    HWPTAG_BEGIN + 4: 'HWPTAG_BORDER_FILL',
    HWPTAG_BEGIN + 5: 'HWPTAG_CHAR_SHAPE',
    HWPTAG_BEGIN + 6: 'HWPTAG_TAB_DEF',
    HWPTAG_BEGIN + 7: 'HWPTAG_NUMBERING',
    HWPTAG_BEGIN + 8: 'HWPTAG_BULLET',
    HWPTAG_BEGIN + 9: 'HWPTAG_PARA_SHAPE',
    HWPTAG_BEGIN + 10: 'HWPTAG_STYLE',
    HWPTAG_BEGIN + 11: 'HWPTAG_DOC_DATA',
    HWPTAG_BEGIN + 12: 'HWPTAG_DISTRIBUTE_DOC_DATA',
    HWPTAG_BEGIN + 13: 'HWPTAG__RESERVED',
    HWPTAG_BEGIN + 14: 'HWPTAG_COMPATIBLE_DOCUMENT',
    HWPTAG_BEGIN + 15: 'HWPTAG_LAYOUT_COMPATIBILITY',
    HWPTAG_BEGIN + 16: 'HWPTAG_TRACKCHANGE',
    HWPTAG_BEGIN + 50: 'HWPTAG_PARA_HEADER',
    HWPTAG_BEGIN + 51: 'HWPTAG_PARA_TEXT',
    HWPTAG_BEGIN + 52: 'HWPTAG_PARA_CHAR_SHAPE',
    HWPTAG_BEGIN + 53: 'HWPTAG_PARA_LINE_SEG',
    HWPTAG_BEGIN + 54: 'HWPTAG_PARA_RANGE_TAG',
    HWPTAG_BEGIN + 55: 'HWPTAG_CTRL_HEADER',
    HWPTAG_BEGIN + 56: 'HWPTAG_LIST_HEADER',
    HWPTAG_BEGIN + 57: 'HWPTAG_PAGE_DEF',
    HWPTAG_BEGIN + 58: 'HWPTAG_FOOTNOTE_SHAPE',
    HWPTAG_BEGIN + 59: 'HWPTAG_PAGE_BORDER_FILL',
    HWPTAG_BEGIN + 60: 'HWPTAG_SHAPE_COMPONENT',
    HWPTAG_BEGIN + 61: 'HWPTAG_TABLE',
    HWPTAG_BEGIN + 62: 'HWPTAG_SHAPE_COMPONENT_LINE',
    HWPTAG_BEGIN + 63: 'HWPTAG_SHAPE_COMPONENT_RECTANGLE',
    HWPTAG_BEGIN + 64: 'HWPTAG_SHAPE_COMPONENT_ELLIPSE',
    HWPTAG_BEGIN + 65: 'HWPTAG_SHAPE_COMPONENT_ARC',
    HWPTAG_BEGIN + 66: 'HWPTAG_SHAPE_COMPONENT_POLYGON',
    HWPTAG_BEGIN + 67: 'HWPTAG_SHAPE_COMPONENT_CURVER',
    HWPTAG_BEGIN + 68: 'HWPTAG_SHAPE_COMPONENT_OLE',
    HWPTAG_BEGIN + 69: 'HWPTAG_SHAPE_COMPONENT_PICTURE',
    HWPTAG_BEGIN + 70: 'HWPTAG_SHAPE_COMPONENT_CONTAINER',
    HWPTAG_BEGIN + 71: 'HWPTAG_CTRL_DATA',
    HWPTAG_BEGIN + 72: 'HWPTAG_EQEDIT',
    HWPTAG_BEGIN + 73: 'HWPTAG_RESERVED',
    HWPTAG_BEGIN + 74: 'HWPTAG_SHAPE_COMPONENT_TEXTART',
    HWPTAG_BEGIN + 75: 'HWPTAG_FORM_OBJECT',
    HWPTAG_BEGIN + 76: 'HWPTAG_MEMO_SHAPE',
    HWPTAG_BEGIN + 77: 'HWPTAG_MEMO_LIST',
    HWPTAG_BEGIN + 76: 'HWPTAG_MEMO_SHAPE',
    HWPTAG_BEGIN + 78: 'HWPTAG_FORBIDDEN_CHAR',
    HWPTAG_BEGIN + 79: 'HWPTAG_CHART_DATA',
    HWPTAG_BEGIN + 80: 'HWPTAG_TRACK_CHANGE',
    HWPTAG_BEGIN + 81: 'HWPTAG_TRACK_CHANGE_AUTHOR',
    HWPTAG_BEGIN + 82: 'HWPTAG_VIDEO_DATA',
    HWPTAG_BEGIN + 99: 'HWPTAG_SHAPE_COMPONENT_UNKNOWN',
}


class char(object):
    size = 1


class inline(object):
    size = 8


class extended(object):
    size = 8


control_char_table = {
    0x00: ('UNUSABLE', char),
    0x01: ('RESERVED0', extended),
    0x02: ('SECTION_OR_COLUMN_DEF', extended),
    0x03: ('FIELD_START', extended),
    0x04: ('FIELD_END', inline),
    0x05: ('RESERVED1', inline),
    0x06: ('RESERVED2', inline),
    0x07: ('RESERVED3', inline),
    0x08: ('TITLE_MARK', inline),
    0x09: ('TAB', inline),
    0x0a: ('LINE_BREAK', char),
    0x0b: ('DRAWING_OR_TABLE', extended),
    0x0c: ('RESERVED4', extended),
    0x0d: ('PARA_BREAK', char),
    0x0e: ('RESERVED5', extended),
    0x0f: ('HIDDEN_EXPLANATION', extended),
    0x10: ('HEADER_OR_FOOTER', extended),
    0x11: ('FOOTNOTE_OR_ENDNOTE', extended),
    0x12: ('AUTO_NUMBERING', extended),
    0x13: ('RESERVED6', inline),
    0x14: ('RESERVED7', inline),
    0x15: ('PAGE_CONTROL', extended),
    0x16: ('BOOKMARK', extended),
    0x17: ('DUTMAL_OR_CHAR_OVERLAP', extended),
    0x18: ('HYPEN', char),
    0x19: ('RESERVED8', char),
    0x1a: ('RESERVED9', char),
    0x1b: ('RESERVED10', char),
    0x1c: ('RESERVED11', char),
    0x1d: ('RESERVED12', char),
    0x1e: ('NONBREAK_SPACE', char),
    0x1f: ('FIXEDWIDTH_SPACE', char),
}
