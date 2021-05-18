
import yaml
import re

def get_version_string():
    cdef const char *value
    value = fy_library_version()
    if PY_MAJOR_VERSION < 3:
        version = value
    else:
        version = PyUnicode_FromString(value)

    return version + ".0"

def get_version():
    cdef int major, minor, patch
    m = re.match(r"(\d+)\.(\d+)", get_version_string())
    major = int(m.group(1))
    minor = int(m.group(2))
    # we ignore patch number for now (libfyaml uses tags so...
    patch = 0
    return (major, minor, patch)

YAMLError = yaml.error.YAMLError
ReaderError = yaml.reader.ReaderError
ScannerError = yaml.scanner.ScannerError
ParserError = yaml.parser.ParserError
ComposerError = yaml.composer.ComposerError
ConstructorError = yaml.constructor.ConstructorError
EmitterError = yaml.emitter.EmitterError
SerializerError = yaml.serializer.SerializerError
RepresenterError = yaml.representer.RepresenterError

StreamStartEvent = yaml.events.StreamStartEvent
StreamEndEvent = yaml.events.StreamEndEvent
DocumentStartEvent = yaml.events.DocumentStartEvent
DocumentEndEvent = yaml.events.DocumentEndEvent
AliasEvent = yaml.events.AliasEvent
ScalarEvent = yaml.events.ScalarEvent
SequenceStartEvent = yaml.events.SequenceStartEvent
SequenceEndEvent = yaml.events.SequenceEndEvent
MappingStartEvent = yaml.events.MappingStartEvent
MappingEndEvent = yaml.events.MappingEndEvent

ScalarNode = yaml.nodes.ScalarNode
SequenceNode = yaml.nodes.SequenceNode
MappingNode = yaml.nodes.MappingNode

StreamStartToken = yaml.tokens.StreamStartToken
StreamEndToken = yaml.tokens.StreamEndToken
DirectiveToken = yaml.tokens.DirectiveToken
DocumentStartToken = yaml.tokens.DocumentStartToken
DocumentEndToken = yaml.tokens.DocumentEndToken
BlockSequenceStartToken = yaml.tokens.BlockSequenceStartToken
BlockMappingStartToken = yaml.tokens.BlockMappingStartToken
BlockEndToken = yaml.tokens.BlockEndToken
FlowSequenceStartToken = yaml.tokens.FlowSequenceStartToken
FlowMappingStartToken = yaml.tokens.FlowMappingStartToken
FlowSequenceEndToken = yaml.tokens.FlowSequenceEndToken
FlowMappingEndToken = yaml.tokens.FlowMappingEndToken
KeyToken = yaml.tokens.KeyToken
ValueToken = yaml.tokens.ValueToken
BlockEntryToken = yaml.tokens.BlockEntryToken
FlowEntryToken = yaml.tokens.FlowEntryToken
AliasToken = yaml.tokens.AliasToken
AnchorToken = yaml.tokens.AnchorToken
TagToken = yaml.tokens.TagToken
ScalarToken = yaml.tokens.ScalarToken

cdef class Mark:
    cdef readonly object name
    cdef readonly size_t index
    cdef readonly size_t line
    cdef readonly size_t column
    cdef readonly buffer
    cdef readonly pointer

    def __init__(self, object name, size_t index, size_t line, size_t column,
            object buffer, object pointer):
        self.name = name
        self.index = index
        self.line = line
        self.column = column
        self.buffer = buffer
        self.pointer = pointer

    def get_snippet(self):
        return None

    def __str__(self):
        where = "  in \"%s\", line %d, column %d"   \
                % (self.name, self.line+1, self.column+1)
        return where

cdef class CParser:

    cdef fy_parser *parser
    # we keep two pointers
    # cython doesn't do anonymous unions so we have to workaround it
    cdef fy_event *parsed_event
    cdef _fy_event *_parsed_event

    cdef object stream
    cdef object stream_name
    cdef object current_token
    cdef object current_event
    cdef object anchors
    cdef object stream_cache
    cdef int stream_cache_len
    cdef int stream_cache_pos
    cdef int unicode_source
    cdef int ret

    def __init__(self, stream):
        cdef is_readable
        cdef fy_parse_cfg cfg

        memset(&cfg, 0, sizeof(cfg))
        cfg.search_path = ""
        cfg.flags = <fy_parse_cfg_flags>(FYPCF_QUIET | FYPCF_DEFAULT_VERSION_1_1 | FYPCF_SLOPPY_FLOW_INDENTATION)

        self.parser = fy_parser_create(&cfg)
        if self.parser == NULL:
            raise MemoryError

        self.parsed_event = NULL
        self._parsed_event = NULL

        # printf("%s: parser created\n", "__init__")
        is_readable = 1
        try:
            stream.read
        except AttributeError:
            is_readable = 0
        self.unicode_source = 0
        if is_readable:
            self.stream = stream
            try:
                self.stream_name = stream.name
            except AttributeError:
                if PY_MAJOR_VERSION < 3:
                    self.stream_name = '<file>'
                else:
                    self.stream_name = u'<file>'
            self.stream_cache = None
            self.stream_cache_len = 0
            self.stream_cache_pos = 0
            ret = fy_parser_set_input_callback(self.parser, <void *>self, input_handler)
            if ret != 0:
                raise MemoryError
        else:
            if PyUnicode_CheckExact(stream) != 0:
                stream = PyUnicode_AsUTF8String(stream)
                if PY_MAJOR_VERSION < 3:
                    self.stream_name = '<unicode string>'
                else:
                    self.stream_name = u'<unicode string>'
                self.unicode_source = 1
            else:
                if PY_MAJOR_VERSION < 3:
                    self.stream_name = '<byte string>'
                else:
                    self.stream_name = u'<byte string>'
            if PyString_CheckExact(stream) == 0:
                if PY_MAJOR_VERSION < 3:
                    raise TypeError("a string or stream input is required")
                else:
                    raise TypeError(u"a string or stream input is required")
            self.stream = stream
            ret = fy_parser_set_string(self.parser, PyString_AS_STRING(stream), PyString_GET_SIZE(stream))
            if ret != 0:
                raise MemoryError

        self.current_token = None
        self.current_event = None
        self.anchors = {}

    def __dealloc__(self):
        fy_parser_event_free(self.parser, self.parsed_event)
        fy_parser_destroy(self.parser)

    def dispose(self):
        pass

    cdef object _parser_error(self):
        # if self.parser.error == YAML_MEMORY_ERROR:
            return MemoryError
        # elif self.parser.error == YAML_READER_ERROR:
        #     if PY_MAJOR_VERSION < 3:
        #         return ReaderError(self.stream_name, self.parser.problem_offset,
        #                 self.parser.problem_value, '?', self.parser.problem)
        #     else:
        #         return ReaderError(self.stream_name, self.parser.problem_offset,
        #                 self.parser.problem_value, u'?', PyUnicode_FromString(self.parser.problem))
        # elif self.parser.error == YAML_SCANNER_ERROR    \
        #         or self.parser.error == YAML_PARSER_ERROR:
        #     context_mark = None
        #     problem_mark = None
        #     if self.parser.context != NULL:
        #         context_mark = Mark(self.stream_name,
        #                 self.parser.context_mark.index,
        #                 self.parser.context_mark.line,
        #                 self.parser.context_mark.column, None, None)
        #     if self.parser.problem != NULL:
        #         problem_mark = Mark(self.stream_name,
        #                 self.parser.problem_mark.index,
        #                 self.parser.problem_mark.line,
        #                 self.parser.problem_mark.column, None, None)
        #     context = None
        #     if self.parser.context != NULL:
        #         if PY_MAJOR_VERSION < 3:
        #             context = self.parser.context
        #         else:
        #             context = PyUnicode_FromString(self.parser.context)
        #     if PY_MAJOR_VERSION < 3:
        #         problem = self.parser.problem
        #     else:
        #         problem = PyUnicode_FromString(self.parser.problem)
        #     if self.parser.error == YAML_SCANNER_ERROR:
        #         return ScannerError(context, context_mark, problem, problem_mark)
        #     else:
        #         return ParserError(context, context_mark, problem, problem_mark)
        # if PY_MAJOR_VERSION < 3:
        #     raise ValueError("no parser error")
        # else:
        #     raise ValueError(u"no parser error")

    def raw_scan(self):
        cdef fy_token *token
        cdef int count
        cdef fy_token_type type

        count = 0
        while True:
            token = fy_scan(self.parser)

            if token == NULL:
                if PY_MAJOR_VERSION < 3:
                    raise ReaderError(self.stream_name, 0, 0, '?', "problem")
                else:
                    raise ReaderError(self.stream_name, 0, 0, u'?', PyUnicode_FromString("problem"))

            type = fy_token_get_type(token)
            # we don't use the token
            fy_scan_token_free(self.parser, token)

            if type == FYTT_NONE:
                break

            count = count+1

        return count

    cdef object _scan(self):
        cdef fy_token *token
        cdef const fy_mark *start_mark
        cdef const fy_mark *end_mark

        while True:
            token = fy_scan(self.parser)
            if token == NULL:
                return None
                if PY_MAJOR_VERSION < 3:
                    raise ReaderError(self.stream_name, 0, 0, '?', "problem")
                else:
                    raise ReaderError(self.stream_name, 0, 0, u'?', PyUnicode_FromString("problem"))

            type = fy_token_get_type(token)
            if type != FYTT_VALUE:
                break
            start_mark = fy_token_start_mark(token)
            end_mark = fy_token_end_mark(token)
            # remove from the token stream the NULL value
            if start_mark[0].input_pos != end_mark[0].input_pos:
                break

        token_object = self._token_to_object(token)
        fy_scan_token_free(self.parser, token)

        return token_object

    cdef object _token_to_object(self, fy_token *token):
        cdef const fy_mark *start_mark
        cdef const fy_mark *end_mark
        cdef fy_token_type type
        cdef const char *text
        cdef size_t textlen
        cdef const fy_version *vers
        cdef const char *prefix
        cdef const char *handle
        cdef const char *suffix
        cdef fy_scalar_style style

        start_mark = fy_token_start_mark(token)
        end_mark = fy_token_end_mark(token)

        start_markp = Mark(self.stream_name, start_mark[0].input_pos, start_mark[0].line, start_mark[0].column, None, None)
        end_markp = Mark(self.stream_name, end_mark[0].input_pos, end_mark[0].line, end_mark[0].column, None, None)

        type = fy_token_get_type(token)

        if type == FYTT_NONE:
            return None

        if type == FYTT_STREAM_START:
            encoding = None
            # libfyaml only does utf-8
            if PY_MAJOR_VERSION < 3:
                encoding = "utf-8"
            else:
                encoding = u"utf-8"
            return StreamStartToken(start_markp, end_markp, encoding)

        if type == FYTT_STREAM_END:
            return StreamEndToken(start_markp, end_markp)

        if type == FYTT_VERSION_DIRECTIVE:

            vers = fy_version_directive_token_version(token)
            if vers == NULL:
                raise MemoryError
            return DirectiveToken(u"YAML", (vers[0].major, vers[0].minor), start_markp, end_markp)

        if type == FYTT_TAG_DIRECTIVE:

            prefix = fy_tag_directive_token_prefix0(token)
            if prefix == NULL:
                raise MemoryError

            handle = fy_tag_directive_token_handle0(token)
            if handle == NULL:
                raise MemoryError

            prefixp = PyUnicode_FromString(prefix)
            handlep = PyUnicode_FromString(handle)

            return DirectiveToken(u"TAG", (handlep, prefixp), start_markp, end_markp)

        if type == FYTT_DOCUMENT_START:
            return DocumentStartToken(start_markp, end_markp)

        if type == FYTT_DOCUMENT_END:
            return DocumentEndToken(start_markp, end_markp)

        if type == FYTT_BLOCK_SEQUENCE_START:
            return BlockSequenceStartToken(start_markp, end_markp)

        if type == FYTT_BLOCK_MAPPING_START:
            return BlockMappingStartToken(start_markp, end_markp)

        if type == FYTT_BLOCK_END:
            return BlockEndToken(start_markp, end_markp)

        if type == FYTT_FLOW_SEQUENCE_START:
            return FlowSequenceStartToken(start_markp, end_markp)

        if type == FYTT_FLOW_SEQUENCE_END:
            return FlowSequenceEndToken(start_markp, end_markp)

        if type == FYTT_FLOW_MAPPING_START:
            return FlowMappingStartToken(start_markp, end_markp)

        if type == FYTT_FLOW_MAPPING_END:
            return FlowMappingEndToken(start_markp, end_markp)

        if type == FYTT_BLOCK_ENTRY:
            return BlockEntryToken(start_markp, end_markp)

        if type == FYTT_FLOW_ENTRY:
            return FlowEntryToken(start_markp, end_markp)

        if type == FYTT_KEY:
            return KeyToken(start_markp, end_markp)

        if type == FYTT_VALUE:
            return ValueToken(start_markp, end_markp)

        if type == FYTT_ALIAS:
            text = fy_token_get_text0(token)
            if text == NULL:
                raise MemoryError

            value = PyUnicode_FromString(text)
            return AliasToken(value, start_markp, end_markp)

        if type == FYTT_ANCHOR:

            text = fy_token_get_text0(token)
            if text == NULL:
                raise MemoryError

            valuep = PyUnicode_FromString(text)
            return AnchorToken(valuep, start_markp, end_markp)

        if type == FYTT_TAG:

            handle = fy_tag_token_handle0(token)
            if handle == NULL:
                raise MemoryError

            suffix = fy_tag_token_suffix0(token)
            if suffix == NULL:
                raise MemoryError

            handlep = PyUnicode_FromString(handle)
            suffixp = PyUnicode_FromString(suffix)

            if suffixp == u'' or suffixp == '':
                suffixp = handlep
                handlep = None

            if handlep == u'' or handlep == '':
                handlep = None

            return TagToken((handlep, suffixp), start_markp, end_markp)

        if type == FYTT_SCALAR:

            text = fy_token_get_text(token, &textlen)
            if text == NULL:
                raise MemoryError

            value = PyUnicode_DecodeUTF8(text, textlen, 'strict')
            plain = False
            stylep = None

            style = fy_scalar_token_get_style(token)

            if style == FYSS_PLAIN:
                plain = True
                # stylep = u'' , plain as None
            else:
                if PY_MAJOR_VERSION < 3:
                    if style == FYSS_SINGLE_QUOTED:
                        stylep = '\''
                    elif style == FYSS_DOUBLE_QUOTED:
                        stylep = '"'
                    elif style == FYSS_LITERAL:
                        stylep = '|'
                    elif style == FYSS_FOLDED:
                        stylep = '>'
                else:
                    if style == FYSS_SINGLE_QUOTED:
                        stylep = u'\''
                    elif style == FYSS_DOUBLE_QUOTED:
                        stylep = u'"'
                    elif style == FYSS_LITERAL:
                        stylep = u'|'
                    elif style == FYSS_FOLDED:
                        stylep = u'>'

            return ScalarToken(value, plain, start_markp, end_markp, stylep)

        if PY_MAJOR_VERSION < 3:
            raise ValueError("unknown token type")
        else:
            raise ValueError(u"unknown token type")

    def get_token(self):
        if self.current_token is not None:
            value = self.current_token
            self.current_token = None
        else:
            value = self._scan()
        return value

    def peek_token(self):
        if self.current_token is None:
            self.current_token = self._scan()
        return self.current_token

    def check_token(self, *choices):
        if self.current_token is None:
            self.current_token = self._scan()
        if self.current_token is None:
            return False
        if not choices:
            return True
        token_class = self.current_token.__class__
        for choice in choices:
            if token_class is choice:
                return True
        return False

    def raw_parse(self):
        cdef fy_event *event
        cdef fy_event_type type
        cdef int count

        count = 0
        while True:
            event = fy_parser_parse(self.parser)
            if event == NULL:
                if PY_MAJOR_VERSION < 3:
                    raise ParserError("unexpected NULL return from fy_parser_parse")
                else:
                    raise ParserError(u"unexpected NULL return from fy_parser_parse")

            type = event.type
            fy_parser_event_free(self.parser, event)

            if type == FYET_NONE:
                break

            count = count+1

        return count

    cdef object _parse(self):
        cdef fy_event *event

        event = fy_parser_parse(self.parser)
        if event == NULL:
            return None
            if PY_MAJOR_VERSION < 3:
                raise ParserError("unexpected NULL return from fy_parser_parse")
            else:
                raise ParserError(u"unexpected NULL return from fy_parser_parse")

        event_object = self._event_to_object(event)
        fy_parser_event_free(self.parser, event)
        return event_object

    cdef object _event_to_object(self, fy_event *event):
        cdef _fy_event *_event
        cdef const fy_mark *start_mark
        cdef const fy_mark *end_mark
        cdef fy_document_state *fyds
        cdef const fy_version *vers
        cdef const fy_tag *tag
        cdef void *tagiter
        cdef const char *text
        cdef size_t textlen
        cdef fy_event_type type
        cdef fy_node_style nstyle

        _event = <_fy_event *>event

        start_mark = fy_event_start_mark(event)
        end_mark = fy_event_end_mark(event)

        if start_mark != NULL:
            start_markp = Mark(self.stream_name, start_mark[0].input_pos, start_mark[0].line, start_mark[0].column, None, None)
        else:
            start_markp = None

        if start_mark != NULL:
            end_markp = Mark(self.stream_name, end_mark[0].input_pos, end_mark[0].line, end_mark[0].column, None, None)
        else:
            end_markp = None

        type = event.type

        if type == FYET_NONE:
            return None

        if type == FYET_STREAM_START:
            encoding = None
            # libfyaml is utf8 only...
            if PY_MAJOR_VERSION < 3:
                encoding = "utf-8"
            else:
                encoding = u"utf-8"
            return StreamStartEvent(start_markp, end_markp, encoding)

        if type == FYET_STREAM_END:
            return StreamEndEvent(start_markp, end_markp)

        if type == FYET_DOCUMENT_START:
            explicit = False
            if _event.data.document_start.implicit == 0:
                explicit = True
            fyds = _event.data.document_start.document_state

            version = None
            if fy_document_state_version_explicit(fyds) == True:
                vers = fy_document_state_version(fyds)
                version = (vers[0].major, vers[0].minor)

            tags = {}
            tagsnr = 0
            if fy_document_state_tags_explicit(fyds) == True:
                tagiter = NULL
                while True:
                    tag = fy_document_state_tag_directive_iterate(fyds, &tagiter)
                    if tag == NULL:
                        break
                    # skip over default tags
                    implicit = fy_document_state_tag_is_default(fyds, tag)
                    if implicit == True:
                        continue

                    handle = PyUnicode_FromString(tag[0].handle)
                    prefix = PyUnicode_FromString(tag[0].prefix)
                    tags[handle] = prefix
                    tagsnr = tagsnr+1

            # if no tags found, set tags to None
            if tagsnr == 0:
                tags = None

            return DocumentStartEvent(start_markp, end_markp, explicit, version, tags)

        if type == FYET_DOCUMENT_END:
            explicit = False
            if _event.data.document_end.implicit == 0:
                explicit = True
            return DocumentEndEvent(start_markp, end_markp, explicit)

        if type == FYET_ALIAS:
            text = fy_token_get_text0(_event.data.alias.anchor)
            if text == NULL:
                raise MemoryError
            anchor = PyUnicode_FromString(text)
            return AliasEvent(anchor, start_markp, end_markp)

        if type == FYET_SCALAR:

            anchor = None
            if _event.data.scalar.anchor != NULL:
                text = fy_token_get_text0(_event.data.scalar.anchor)
                if text == NULL:
                    raise MemoryError
                anchor = PyUnicode_FromString(text)

            tagp = None
            if _event.data.scalar.tag != NULL:
                text = fy_token_get_text0(_event.data.scalar.tag)
                if text == NULL:
                    raise MemoryError
                tagp = PyUnicode_FromString(text)

            text = fy_token_get_text(_event.data.scalar.value, &textlen)
            if text == NULL:
                raise MemoryError

            value = PyUnicode_DecodeUTF8(text, textlen, 'strict')

            stylep = None
            style = fy_token_scalar_style(_event.data.scalar.value)

            if PY_MAJOR_VERSION < 3:
                if style == FYSS_PLAIN:
                    stylep = ''
                elif style == FYSS_SINGLE_QUOTED:
                    stylep = '\''
                elif style == FYSS_DOUBLE_QUOTED:
                    stylep = '"'
                elif style == FYSS_LITERAL:
                    stylep = '|'
                elif style == FYSS_FOLDED:
                    stylep = '>'

                if (style == FYSS_PLAIN and tagp is None) or tagp == u'!':
                    implicit = (True, False)
                elif tagp is None:
                    implicit = (False, True)
                else:
                    implicit = (False, False)

            else:
                if style == FYSS_PLAIN:
                    stylep = u''
                elif style == FYSS_SINGLE_QUOTED:
                    stylep = u'\''
                elif style == FYSS_DOUBLE_QUOTED:
                    stylep = u'"'
                elif style == FYSS_LITERAL:
                    stylep = u'|'
                elif style == FYSS_FOLDED:
                    stylep = u'>'

                if (style == FYSS_PLAIN and tagp is None) or tagp == '!':
                    implicit = (True, False)
                elif tagp is None:
                    implicit = (False, True)
                else:
                    implicit = (False, False)

            return ScalarEvent(anchor, tagp, implicit, value, start_markp, end_markp, stylep)

        if type == FYET_SEQUENCE_START:
            anchor = None
            if _event.data.sequence_start.anchor != NULL:
                text = fy_token_get_text0(_event.data.sequence_start.anchor)
                if text == NULL:
                    raise MemoryError
                anchor = PyUnicode_FromString(text)

            tagp = None
            if _event.data.sequence_start.tag != NULL:
                text = fy_token_get_text0(_event.data.sequence_start.tag)
                if text == NULL:
                    raise MemoryError
                tagp = PyUnicode_FromString(text)

            if PY_MAJOR_VERSION < 3:
                implicit = (tagp is None or tagp == u'!')
            else:
                implicit = (tagp is None or tagp == '!')

            flow_style = None
            nstyle = fy_event_get_node_style(event)
            if nstyle == FYNS_FLOW:
                flow_style = True
            elif nstyle == FYNS_BLOCK:
                flow_style = False

            return SequenceStartEvent(anchor, tagp, implicit, start_markp, end_markp, flow_style)

        if type == FYET_MAPPING_START:
            anchor = None
            if _event.data.mapping_start.anchor != NULL:
                text = fy_token_get_text0(_event.data.mapping_start.anchor)
                if text == NULL:
                    raise MemoryError
                anchor = PyUnicode_FromString(text)

            tagp = None
            if _event.data.mapping_start.tag != NULL:
                text = fy_token_get_text0(_event.data.mapping_start.tag)
                if text == NULL:
                    raise MemoryError
                tagp = PyUnicode_FromString(text)

            if PY_MAJOR_VERSION < 3:
                implicit = (tagp is None or tagp == u'!')
            else:
                implicit = (tagp is None or tagp == '!')

            flow_style = None
            nstyle = fy_event_get_node_style(event)
            if nstyle == FYNS_FLOW:
                flow_style = True
            elif nstyle == FYNS_BLOCK:
                flow_style = False

            return MappingStartEvent(anchor, tagp, implicit, start_markp, end_markp, flow_style)

        if type == FYET_SEQUENCE_END:
            return SequenceEndEvent(start_markp, end_markp)

        if type == FYET_MAPPING_END:
            return MappingEndEvent(start_markp, end_markp)

        if PY_MAJOR_VERSION < 3:
            raise ValueError("unknown event type")
        else:
            raise ValueError(u"unknown event type")

    def get_event(self):
        if self.current_event is not None:
            value = self.current_event
            self.current_event = None
        else:
            value = self._parse()
        return value

    def peek_event(self):
        if self.current_event is None:
            self.current_event = self._parse()
        return self.current_event

    def check_event(self, *choices):
        if self.current_event is None:
            self.current_event = self._parse()
        if self.current_event is None:
            return False
        if not choices:
            return True
        event_class = self.current_event.__class__
        for choice in choices:
            if event_class is choice:
                return True
        return False

    def check_node(self):
        self._parse_next_event()
        if self.parsed_event.type == FYET_STREAM_START:
            fy_parser_event_free(self.parser, self.parsed_event)
            self.parsed_event = NULL
            self._parsed_event = NULL
            self._parse_next_event()
        if self.parsed_event.type != FYET_STREAM_END:
            return True
        return False

    def get_node(self):
        # printf("get_node\n")
        self._parse_next_event()

        self._parse_next_event()
        if self.parsed_event.type == FYET_STREAM_END:
            return None

        self._parse_free_event()

        node = self._compose_node(None, None)
        self.anchors = {}

        self._parse_free_event()
        self._parse_next_event()

        return None

    def get_single_node(self):
        cdef const fy_mark *start_mark

        # print("get_single_node\n")

        self._parse_next_event()
        if self.parsed_event.type != FYET_STREAM_START:
            raise ComposerError("Parser not starting with stream start")
        # print "got FYET_STREAM_START"
        self._parse_free_event()

        document = None
        self._parse_next_event()

        if self.parsed_event.type != FYET_DOCUMENT_START:
            raise ComposerError("Parser not producing document start")
        # print "got FYET_DOCUMENT_START"
        self._parse_free_event()

        node = self._compose_node(None, None)
        self.anchors = {}

        self._parse_next_event()
        if self.parsed_event.type != FYET_DOCUMENT_END:
            raise ComposerError("Parser not producing document end")
        # print "got FYET_DOCUMENT_END"
        self._parse_free_event()

        self._parse_next_event()
        if self.parsed_event.type == FYET_STREAM_END:
            # print "got FYET_STREAM_END"
            self._parse_free_event()
            return node

        if self.parsed_event.type != FYET_DOCUMENT_START:
            raise ComposerError("Parser not producing document start (on error)")

        # multi document
        start_mark = fy_event_start_mark(self.parsed_event)
        if start_mark != NULL:
            mark = Mark(self.stream_name, start_mark[0].input_pos, start_mark[0].line, start_mark[0].column, None, None)
        else:
            mark = None

        if PY_MAJOR_VERSION < 3:
            raise ComposerError("expected a single document in the stream",
                    document.start_mark, "but found another document", mark)
        else:
            raise ComposerError(u"expected a single document in the stream",
                    document.start_mark, u"but found another document", mark)

    cdef object _compose_node(self, object parent, object index):
        # printf("_compose_node\n")
        cdef const char *anchor_str
        cdef const char *tagstr
        cdef const fy_mark *start_mark
        cdef fy_token *anchor_token

        self._parse_next_event()

        if self.parsed_event.type == FYET_ALIAS:

            anchor_str = fy_token_get_text0(self._parsed_event.data.alias.anchor)
            if anchor_str == NULL:
                raise MemoryError

            anchor = PyUnicode_FromString(anchor_str)

            if anchor in self.anchors:
                self._parse_free_event()
                return self.anchors[anchor]

            start_mark = fy_event_start_mark(self.parsed_event)

            mark = Mark(self.stream_name, start_mark[0].input_pos, start_mark[0].line, start_mark[0].column, None, None)
            if PY_MAJOR_VERSION < 3:
                raise ComposerError(None, None, "found undefined alias", mark)
            else:
                raise ComposerError(None, None, u"found undefined alias", mark)

        # get the anchor (if any)
        anchor_token = NULL
        if self.parsed_event.type == FYET_SCALAR:
            anchor_token = self._parsed_event.data.scalar.anchor
        elif self.parsed_event.type == FYET_SEQUENCE_START:
            anchor_token = self._parsed_event.data.sequence_start.anchor
        elif self.parsed_event.type == FYET_MAPPING_START:
            anchor_token = self._parsed_event.data.mapping_start.anchor

        # check duplicate anchor
        if anchor_token != NULL:
            anchor_str = fy_token_get_text0(anchor_token)
            if anchor_str == NULL:
                raise MemoryError
            anchor = PyUnicode_FromString(anchor_str)
        else:
            anchor = None

        if anchor != None and anchor in self.anchors:

            start_mark = fy_event_start_mark(self.parsed_event)

            mark = Mark(self.stream_name,
                    start_mark[0].input_pos,
                    start_mark[0].line,
                    start_mark[0].column,
                    None, None)
            if PY_MAJOR_VERSION < 3:
                raise ComposerError("found duplicate anchor; first occurrence",
                        self.anchors[anchor].start_mark, "second occurrence", mark)
            else:
                raise ComposerError(u"found duplicate anchor; first occurrence",
                        self.anchors[anchor].start_mark, u"second occurrence", mark)

        self.descend_resolver(parent, index)

        if self.parsed_event.type == FYET_SCALAR:
            node = self._compose_scalar_node(anchor)
        elif self.parsed_event.type == FYET_SEQUENCE_START:
            node = self._compose_sequence_node(anchor)
        elif self.parsed_event.type == FYET_MAPPING_START:
            node = self._compose_mapping_node(anchor)
        self.ascend_resolver()
        return node

    cdef _compose_scalar_node(self, object anchor):
        # printf("_compose_scalar_node\n")
        cdef const fy_mark *start_mark
        cdef const fy_mark *end_mark
        cdef const char *str
        cdef size_t len
        cdef const char *tag_str
        cdef fy_scalar_style style

        start_mark = fy_event_start_mark(self.parsed_event)
        end_mark = fy_event_end_mark(self.parsed_event)

        start_markp = Mark(self.stream_name, start_mark[0].input_pos, start_mark[0].line, start_mark[0].column, None, None)
        end_markp = Mark(self.stream_name, end_mark[0].input_pos, end_mark[0].line, end_mark[0].column, None, None)

        str = fy_token_get_text(self._parsed_event.data.scalar.value, &len)
        if str == NULL:
             raise MemoryError
        value = PyUnicode_DecodeUTF8(str, len, 'strict')

        # wtf are those...
        plain_implicit = False
        quoted_implicit = False

        if self._parsed_event.data.scalar.tag == NULL:
            tag = self.resolve(ScalarNode, value, (plain_implicit, quoted_implicit))
        else:
            tag_str = fy_token_get_text0(self._parsed_event.data.scalar.tag)
            if tag_str == NULL:
                raise MemoryError

            if tag_str[0] == c'!' and tag_str[1] == c'\0':
                tag = self.resolve(ScalarNode, value, (plain_implicit, quoted_implicit))
            else:
                tag = PyUnicode_FromString(tag_str)

        stylep = None
        style = fy_token_scalar_style(self._parsed_event.data.scalar.value)
        if style == FYSS_PLAIN:
            stylep = u''
        elif style == FYSS_SINGLE_QUOTED:
            stylep = u'\''
        elif style == FYSS_DOUBLE_QUOTED:
            stylep = u'"'
        elif style == FYSS_LITERAL:
            stylep = u'|'
        elif style == FYSS_FOLDED:
            stylep = u'>'

        node = ScalarNode(tag, value, start_markp, end_markp, stylep)

        if anchor is not None:
            self.anchors[anchor] = node

        self._parse_free_event()
        return node

    cdef _compose_sequence_node(self, object anchor):
        # printf("_compose_sequence_node\n")
        cdef const fy_mark *start_mark
        cdef const fy_mark *end_mark
        cdef fy_node_style nstyle
        cdef const char *tag_str
        cdef int index

        start_mark = fy_event_start_mark(self.parsed_event)

        start_markp = Mark(self.stream_name, start_mark[0].input_pos, start_mark[0].line, start_mark[0].column, None, None)
        implicit = False
        if self._parsed_event.data.sequence_start.sequence_start == NULL:
            implicit = True

        if self._parsed_event.data.sequence_start.tag == NULL:
            tag = self.resolve(SequenceNode, None, implicit)
        else:
            tag_str = fy_token_get_text0(self._parsed_event.data.sequence_start.tag)
            if tag_str == NULL:
                raise MemoryError

            if tag_str[0] == c'!' and tag_str[1] == c'\0':
                tag = self.resolve(SequenceNode, None, implicit)
            else:
                tag = PyUnicode_FromString(tag_str)

        flow_style = None
        nstyle = fy_event_get_node_style(self.parsed_event)
        if nstyle == FYNS_FLOW:
            flow_style = True
        elif nstyle == FYNS_BLOCK:
            flow_style = False
        value = []
        node = SequenceNode(tag, value, start_markp, None, flow_style)
        if anchor is not None:
            self.anchors[anchor] = node

        self._parse_free_event()

        index = 0
        self._parse_next_event()
        while self.parsed_event.type != FYET_SEQUENCE_END:
            value.append(self._compose_node(node, index))
            index = index+1
            self._parse_next_event()

        end_mark = fy_event_end_mark(self.parsed_event)

        node.end_mark = Mark(self.stream_name, end_mark[0].input_pos, end_mark[0].line, end_mark[0].column, None, None)

        self._parse_free_event()
        return node

    cdef _compose_mapping_node(self, object anchor):
        # print "_compose_mapping_node"
        cdef const fy_mark *start_mark
        cdef const fy_mark *end_mark
        cdef fy_node_style nstyle
        cdef const char *tag_str
        cdef int index

        start_mark = fy_event_start_mark(self.parsed_event)

        start_markp = Mark(self.stream_name, start_mark[0].input_pos, start_mark[0].line, start_mark[0].column, None, None)
        implicit = False
        if self._parsed_event.data.mapping_start.mapping_start == NULL:
            implicit = True

        if self._parsed_event.data.mapping_start.tag == NULL:
            tag = self.resolve(MappingNode, None, implicit)
        else:
            tag_str = fy_token_get_text0(self._parsed_event.data.mapping_start.tag)
            if tag_str == NULL:
                raise MemoryError

            if tag_str[0] == c'!' and tag_str[1] == c'\0':
                tag = self.resolve(MappingNode, None, implicit)
            else:
                tag = PyUnicode_FromString(tag_str)

        flow_style = None
        nstyle = fy_event_get_node_style(self.parsed_event)
        if nstyle == FYNS_FLOW:
            flow_style = True
        elif nstyle == FYNS_BLOCK:
            flow_style = False
        value = []
        node = MappingNode(tag, value, start_markp, None, flow_style)
        if anchor is not None:
            self.anchors[anchor] = node

        self._parse_free_event()

        index = 0
        self._parse_next_event()
        while self.parsed_event.type != FYET_MAPPING_END:
            item_key = self._compose_node(node, None)
            item_value = self._compose_node(node, item_key)
            value.append((item_key, item_value))
            self._parse_next_event()

        end_mark = fy_event_end_mark(self.parsed_event)

        node.end_mark = Mark(self.stream_name, end_mark[0].input_pos, end_mark[0].line, end_mark[0].column, None, None)

        self._parse_free_event()
        return node

    cdef char *_parsed_event_str(self):
        if self.parsed_event == NULL:
            return "NULL"
        elif self.parsed_event.type == FYET_NONE:
            return "NONE"
        elif self.parsed_event.type == FYET_STREAM_START:
            return "STREAM_START"
        elif self.parsed_event.type == FYET_STREAM_END:
            return "STREAM_END"
        elif self.parsed_event.type == FYET_DOCUMENT_START:
            return "DOCUMENT_START"
        elif self.parsed_event.type == FYET_DOCUMENT_END:
            return "DOCUMENT_END"
        elif self.parsed_event.type == FYET_MAPPING_START:
            return "MAPPING_START"
        elif self.parsed_event.type == FYET_MAPPING_END:
            return "MAPPING_END"
        elif self.parsed_event.type == FYET_SEQUENCE_START:
            return "SEQUENCE_START"
        elif self.parsed_event.type == FYET_SEQUENCE_END:
            return "SEQUENCE_END"
        elif self.parsed_event.type == FYET_SCALAR:
            return "SCALAR"
        elif self.parsed_event.type == FYET_ALIAS:
            return "ALIAS"

        return "UNKONWN"

    cdef void _parse_free_event(self):
        fy_parser_event_free(self.parser, self.parsed_event)
        self.parsed_event = NULL
        self._parsed_event = NULL

    cdef int _parse_next_event(self) except 0:

        if self.parsed_event != NULL:
            return 1

        self.parsed_event = fy_parser_parse(self.parser)

        if self.parsed_event != NULL:
            self._parsed_event = <_fy_event *>self.parsed_event
            return 1

        if PY_MAJOR_VERSION < 3:
            raise ComposerError("unexpected NULL return from fy_parser_parse")
        else:
            raise ComposerError(u"unexpected NULL return from fy_parser_parse")

cdef ssize_t input_handler(void *user, void *buf, size_t size):
    cdef CParser parser
    parser = <CParser>user

    if parser.stream_cache is None:
        value = parser.stream.read(size)
        if PyUnicode_CheckExact(value) != 0:
            value = PyUnicode_AsUTF8String(value)
            parser.unicode_source = 1
        if PyString_CheckExact(value) == 0:
            if PY_MAJOR_VERSION < 3:
                raise TypeError("a string value is expected")
            else:
                raise TypeError(u"a string value is expected")
        parser.stream_cache = value
        parser.stream_cache_pos = 0
        parser.stream_cache_len = PyString_GET_SIZE(value)

    if (parser.stream_cache_len - parser.stream_cache_pos) < size:
        size = parser.stream_cache_len - parser.stream_cache_pos

    if size > 0:
        memcpy(buf, PyString_AS_STRING(parser.stream_cache) + parser.stream_cache_pos, size)
    parser.stream_cache_pos += size
    if parser.stream_cache_pos == parser.stream_cache_len:
        parser.stream_cache = None

    return size

cdef class CEmitter:

    cdef fy_emitter *emitter

    cdef object stream

    cdef int document_start_implicit
    cdef int document_end_implicit
    cdef object use_version
    cdef object use_tags

    cdef object serialized_nodes
    cdef object anchors
    cdef int last_alias_id
    cdef int closed
    cdef int dump_unicode
    cdef object use_encoding

    def __init__(self, stream, canonical=None, indent=None, width=None, allow_unicode=None, line_break=None, encoding=None, explicit_start=None, explicit_end=None, version=None, tags=None):
        self.emitter = fy_emitter_create(NULL)
        if self.emitter == NULL:
             raise MemoryError
        # self.stream = stream
        # self.dump_unicode = 0
        # if PY_MAJOR_VERSION < 3:
        #     if getattr3(stream, 'encoding', None):
        #         self.dump_unicode = 1
        # else:
        #     if hasattr(stream, u'encoding'):
        #         self.dump_unicode = 1
        # self.use_encoding = encoding
        # yaml_emitter_set_output(&self.emitter, output_handler, <void *>self)
        # if canonical:
        #     yaml_emitter_set_canonical(&self.emitter, 1)
        # if indent is not None:
        #     yaml_emitter_set_indent(&self.emitter, indent)
        # if width is not None:
        #     yaml_emitter_set_width(&self.emitter, width)
        # if allow_unicode:
        #     yaml_emitter_set_unicode(&self.emitter, 1)
        # if line_break is not None:
        #     if line_break == '\r':
        #         yaml_emitter_set_break(&self.emitter, YAML_CR_BREAK)
        #     elif line_break == '\n':
        #         yaml_emitter_set_break(&self.emitter, YAML_LN_BREAK)
        #     elif line_break == '\r\n':
        #         yaml_emitter_set_break(&self.emitter, YAML_CRLN_BREAK)
        # self.document_start_implicit = 1
        # if explicit_start:
        #     self.document_start_implicit = 0
        # self.document_end_implicit = 1
        # if explicit_end:
        #     self.document_end_implicit = 0
        # self.use_version = version
        # self.use_tags = tags
        # self.serialized_nodes = {}
        # self.anchors = {}
        # self.last_alias_id = 0
        # self.closed = -1

    def __dealloc__(self):
        fy_emitter_destroy(self.emitter)

    def dispose(self):
        pass

    cdef object _emitter_error(self):
        # if self.emitter.error == YAML_MEMORY_ERROR:
        #     return MemoryError
        # elif self.emitter.error == YAML_EMITTER_ERROR:
        #     if PY_MAJOR_VERSION < 3:
        #         problem = self.emitter.problem
        #     else:
        #         problem = PyUnicode_FromString(self.emitter.problem)
        #     return EmitterError(problem)
        # if PY_MAJOR_VERSION < 3:
        #     raise ValueError("no emitter error")
        # else:
        #     raise ValueError(u"no emitter error")
        return None

    cdef int _object_to_event(self, object event_object, fy_event *event) except 0:
        # cdef yaml_encoding_t encoding
        # cdef yaml_version_directive_t version_directive_value
        # cdef yaml_version_directive_t *version_directive
        # cdef yaml_tag_directive_t tag_directives_value[128]
        # cdef yaml_tag_directive_t *tag_directives_start
        # cdef yaml_tag_directive_t *tag_directives_end
        # cdef int implicit
        # cdef int plain_implicit
        # cdef int quoted_implicit
        # cdef char *anchor
        # cdef char *tag
        # cdef char *value
        # cdef int length
        # cdef yaml_scalar_style_t scalar_style
        # cdef yaml_sequence_style_t sequence_style
        # cdef yaml_mapping_style_t mapping_style
        # event_class = event_object.__class__
        # if event_class is StreamStartEvent:
        #     encoding = YAML_UTF8_ENCODING
        #     if event_object.encoding == u'utf-16-le' or event_object.encoding == 'utf-16-le':
        #         encoding = YAML_UTF16LE_ENCODING
        #     elif event_object.encoding == u'utf-16-be' or event_object.encoding == 'utf-16-be':
        #         encoding = YAML_UTF16BE_ENCODING
        #     if event_object.encoding is None:
        #         self.dump_unicode = 1
        #     if self.dump_unicode == 1:
        #         encoding = YAML_UTF8_ENCODING
        #     yaml_stream_start_event_initialize(event, encoding)
        # elif event_class is StreamEndEvent:
        #     yaml_stream_end_event_initialize(event)
        # elif event_class is DocumentStartEvent:
        #     version_directive = NULL
        #     if event_object.version:
        #         version_directive_value.major = event_object.version[0]
        #         version_directive_value.minor = event_object.version[1]
        #         version_directive = &version_directive_value
        #     tag_directives_start = NULL
        #     tag_directives_end = NULL
        #     if event_object.tags:
        #         if len(event_object.tags) > 128:
        #             if PY_MAJOR_VERSION < 3:
        #                 raise ValueError("too many tags")
        #             else:
        #                 raise ValueError(u"too many tags")
        #         tag_directives_start = tag_directives_value
        #         tag_directives_end = tag_directives_value
        #         cache = []
        #         for handle in event_object.tags:
        #             prefix = event_object.tags[handle]
        #             if PyUnicode_CheckExact(handle):
        #                 handle = PyUnicode_AsUTF8String(handle)
        #                 cache.append(handle)
        #             if not PyString_CheckExact(handle):
        #                 if PY_MAJOR_VERSION < 3:
        #                     raise TypeError("tag handle must be a string")
        #                 else:
        #                     raise TypeError(u"tag handle must be a string")
        #             tag_directives_end.handle = PyString_AS_STRING(handle)
        #             if PyUnicode_CheckExact(prefix):
        #                 prefix = PyUnicode_AsUTF8String(prefix)
        #                 cache.append(prefix)
        #             if not PyString_CheckExact(prefix):
        #                 if PY_MAJOR_VERSION < 3:
        #                     raise TypeError("tag prefix must be a string")
        #                 else:
        #                     raise TypeError(u"tag prefix must be a string")
        #             tag_directives_end.prefix = PyString_AS_STRING(prefix)
        #             tag_directives_end = tag_directives_end+1
        #     implicit = 1
        #     if event_object.explicit:
        #         implicit = 0
        #     if yaml_document_start_event_initialize(event, version_directive,
        #             tag_directives_start, tag_directives_end, implicit) == 0:
        #         raise MemoryError
        # elif event_class is DocumentEndEvent:
        #     implicit = 1
        #     if event_object.explicit:
        #         implicit = 0
        #     yaml_document_end_event_initialize(event, implicit)
        # elif event_class is AliasEvent:
        #     anchor = NULL
        #     anchor_object = event_object.anchor
        #     if PyUnicode_CheckExact(anchor_object):
        #         anchor_object = PyUnicode_AsUTF8String(anchor_object)
        #     if not PyString_CheckExact(anchor_object):
        #         if PY_MAJOR_VERSION < 3:
        #             raise TypeError("anchor must be a string")
        #         else:
        #             raise TypeError(u"anchor must be a string")
        #     anchor = PyString_AS_STRING(anchor_object)
        #     if yaml_alias_event_initialize(event, anchor) == 0:
        #         raise MemoryError
        # elif event_class is ScalarEvent:
        #     anchor = NULL
        #     anchor_object = event_object.anchor
        #     if anchor_object is not None:
        #         if PyUnicode_CheckExact(anchor_object):
        #             anchor_object = PyUnicode_AsUTF8String(anchor_object)
        #         if not PyString_CheckExact(anchor_object):
        #             if PY_MAJOR_VERSION < 3:
        #                 raise TypeError("anchor must be a string")
        #             else:
        #                 raise TypeError(u"anchor must be a string")
        #         anchor = PyString_AS_STRING(anchor_object)
        #     tag = NULL
        #     tag_object = event_object.tag
        #     if tag_object is not None:
        #         if PyUnicode_CheckExact(tag_object):
        #             tag_object = PyUnicode_AsUTF8String(tag_object)
        #         if not PyString_CheckExact(tag_object):
        #             if PY_MAJOR_VERSION < 3:
        #                 raise TypeError("tag must be a string")
        #             else:
        #                 raise TypeError(u"tag must be a string")
        #         tag = PyString_AS_STRING(tag_object)
        #     value_object = event_object.value
        #     if PyUnicode_CheckExact(value_object):
        #         value_object = PyUnicode_AsUTF8String(value_object)
        #     if not PyString_CheckExact(value_object):
        #         if PY_MAJOR_VERSION < 3:
        #             raise TypeError("value must be a string")
        #         else:
        #             raise TypeError(u"value must be a string")
        #     value = PyString_AS_STRING(value_object)
        #     length = PyString_GET_SIZE(value_object)
        #     plain_implicit = 0
        #     quoted_implicit = 0
        #     if event_object.implicit is not None:
        #         plain_implicit = event_object.implicit[0]
        #         quoted_implicit = event_object.implicit[1]
        #     style_object = event_object.style
        #     scalar_style = YAML_PLAIN_SCALAR_STYLE
        #     if style_object == "'" or style_object == u"'":
        #         scalar_style = YAML_SINGLE_QUOTED_SCALAR_STYLE
        #     elif style_object == "\"" or style_object == u"\"":
        #         scalar_style = YAML_DOUBLE_QUOTED_SCALAR_STYLE
        #     elif style_object == "|" or style_object == u"|":
        #         scalar_style = YAML_LITERAL_SCALAR_STYLE
        #     elif style_object == ">" or style_object == u">":
        #         scalar_style = YAML_FOLDED_SCALAR_STYLE
        #     if yaml_scalar_event_initialize(event, anchor, tag, value, length,
        #             plain_implicit, quoted_implicit, scalar_style) == 0:
        #         raise MemoryError
        # elif event_class is SequenceStartEvent:
        #     anchor = NULL
        #     anchor_object = event_object.anchor
        #     if anchor_object is not None:
        #         if PyUnicode_CheckExact(anchor_object):
        #             anchor_object = PyUnicode_AsUTF8String(anchor_object)
        #         if not PyString_CheckExact(anchor_object):
        #             if PY_MAJOR_VERSION < 3:
        #                 raise TypeError("anchor must be a string")
        #             else:
        #                 raise TypeError(u"anchor must be a string")
        #         anchor = PyString_AS_STRING(anchor_object)
        #     tag = NULL
        #     tag_object = event_object.tag
        #     if tag_object is not None:
        #         if PyUnicode_CheckExact(tag_object):
        #             tag_object = PyUnicode_AsUTF8String(tag_object)
        #         if not PyString_CheckExact(tag_object):
        #             if PY_MAJOR_VERSION < 3:
        #                 raise TypeError("tag must be a string")
        #             else:
        #                 raise TypeError(u"tag must be a string")
        #         tag = PyString_AS_STRING(tag_object)
        #     implicit = 0
        #     if event_object.implicit:
        #         implicit = 1
        #     sequence_style = YAML_BLOCK_SEQUENCE_STYLE
        #     if event_object.flow_style:
        #         sequence_style = YAML_FLOW_SEQUENCE_STYLE
        #     if yaml_sequence_start_event_initialize(event, anchor, tag,
        #             implicit, sequence_style) == 0:
        #         raise MemoryError
        # elif event_class is MappingStartEvent:
        #     anchor = NULL
        #     anchor_object = event_object.anchor
        #     if anchor_object is not None:
        #         if PyUnicode_CheckExact(anchor_object):
        #             anchor_object = PyUnicode_AsUTF8String(anchor_object)
        #         if not PyString_CheckExact(anchor_object):
        #             if PY_MAJOR_VERSION < 3:
        #                 raise TypeError("anchor must be a string")
        #             else:
        #                 raise TypeError(u"anchor must be a string")
        #         anchor = PyString_AS_STRING(anchor_object)
        #     tag = NULL
        #     tag_object = event_object.tag
        #     if tag_object is not None:
        #         if PyUnicode_CheckExact(tag_object):
        #             tag_object = PyUnicode_AsUTF8String(tag_object)
        #         if not PyString_CheckExact(tag_object):
        #             if PY_MAJOR_VERSION < 3:
        #                 raise TypeError("tag must be a string")
        #             else:
        #                 raise TypeError(u"tag must be a string")
        #         tag = PyString_AS_STRING(tag_object)
        #     implicit = 0
        #     if event_object.implicit:
        #         implicit = 1
        #     mapping_style = YAML_BLOCK_MAPPING_STYLE
        #     if event_object.flow_style:
        #         mapping_style = YAML_FLOW_MAPPING_STYLE
        #     if yaml_mapping_start_event_initialize(event, anchor, tag,
        #             implicit, mapping_style) == 0:
        #         raise MemoryError
        # elif event_class is SequenceEndEvent:
        #     yaml_sequence_end_event_initialize(event)
        # elif event_class is MappingEndEvent:
        #     yaml_mapping_end_event_initialize(event)
        # else:
        #     if PY_MAJOR_VERSION < 3:
        #         raise TypeError("invalid event %s" % event_object)
        #     else:
        #         raise TypeError(u"invalid event %s" % event_object)
        # return 1
        return None

    def emit(self, event_object):
        # cdef yaml_event_t event
        # self._object_to_event(event_object, &event)
        # if yaml_emitter_emit(&self.emitter, &event) == 0:
        #     error = self._emitter_error()
        #     raise error
        return None

    def open(self):
        # cdef yaml_event_t event
        # cdef yaml_encoding_t encoding
        # if self.closed == -1:
        #     if self.use_encoding == u'utf-16-le' or self.use_encoding == 'utf-16-le':
        #         encoding = YAML_UTF16LE_ENCODING
        #     elif self.use_encoding == u'utf-16-be' or self.use_encoding == 'utf-16-be':
        #         encoding = YAML_UTF16BE_ENCODING
        #     else:
        #         encoding = YAML_UTF8_ENCODING
        #     if self.use_encoding is None:
        #         self.dump_unicode = 1
        #     if self.dump_unicode == 1:
        #         encoding = YAML_UTF8_ENCODING
        #     yaml_stream_start_event_initialize(&event, encoding)
        #     if yaml_emitter_emit(&self.emitter, &event) == 0:
        #         error = self._emitter_error()
        #         raise error
        #     self.closed = 0
        # elif self.closed == 1:
        #     if PY_MAJOR_VERSION < 3:
        #         raise SerializerError("serializer is closed")
        #     else:
        #         raise SerializerError(u"serializer is closed")
        # else:
        #     if PY_MAJOR_VERSION < 3:
        #         raise SerializerError("serializer is already opened")
        #     else:
        #         raise SerializerError(u"serializer is already opened")
        return None

    def close(self):
        # cdef yaml_event_t event
        # if self.closed == -1:
        #     if PY_MAJOR_VERSION < 3:
        #         raise SerializerError("serializer is not opened")
        #     else:
        #         raise SerializerError(u"serializer is not opened")
        # elif self.closed == 0:
        #     yaml_stream_end_event_initialize(&event)
        #     if yaml_emitter_emit(&self.emitter, &event) == 0:
        #         error = self._emitter_error()
        #         raise error
        #     self.closed = 1
        return None

    def serialize(self, node):
        # cdef yaml_event_t event
        # cdef yaml_version_directive_t version_directive_value
        # cdef yaml_version_directive_t *version_directive
        # cdef yaml_tag_directive_t tag_directives_value[128]
        # cdef yaml_tag_directive_t *tag_directives_start
        # cdef yaml_tag_directive_t *tag_directives_end
        # if self.closed == -1:
        #     if PY_MAJOR_VERSION < 3:
        #         raise SerializerError("serializer is not opened")
        #     else:
        #         raise SerializerError(u"serializer is not opened")
        # elif self.closed == 1:
        #     if PY_MAJOR_VERSION < 3:
        #         raise SerializerError("serializer is closed")
        #     else:
        #         raise SerializerError(u"serializer is closed")
        # cache = []
        # version_directive = NULL
        # if self.use_version:
        #     version_directive_value.major = self.use_version[0]
        #     version_directive_value.minor = self.use_version[1]
        #     version_directive = &version_directive_value
        # tag_directives_start = NULL
        # tag_directives_end = NULL
        # if self.use_tags:
        #     if len(self.use_tags) > 128:
        #         if PY_MAJOR_VERSION < 3:
        #             raise ValueError("too many tags")
        #         else:
        #             raise ValueError(u"too many tags")
        #     tag_directives_start = tag_directives_value
        #     tag_directives_end = tag_directives_value
        #     for handle in self.use_tags:
        #         prefix = self.use_tags[handle]
        #         if PyUnicode_CheckExact(handle):
        #             handle = PyUnicode_AsUTF8String(handle)
        #             cache.append(handle)
        #         if not PyString_CheckExact(handle):
        #             if PY_MAJOR_VERSION < 3:
        #                 raise TypeError("tag handle must be a string")
        #             else:
        #                 raise TypeError(u"tag handle must be a string")
        #         tag_directives_end.handle = PyString_AS_STRING(handle)
        #         if PyUnicode_CheckExact(prefix):
        #             prefix = PyUnicode_AsUTF8String(prefix)
        #             cache.append(prefix)
        #         if not PyString_CheckExact(prefix):
        #             if PY_MAJOR_VERSION < 3:
        #                 raise TypeError("tag prefix must be a string")
        #             else:
        #                 raise TypeError(u"tag prefix must be a string")
        #         tag_directives_end.prefix = PyString_AS_STRING(prefix)
        #         tag_directives_end = tag_directives_end+1
        # if yaml_document_start_event_initialize(&event, version_directive,
        #         tag_directives_start, tag_directives_end,
        #         self.document_start_implicit) == 0:
        #     raise MemoryError
        # if yaml_emitter_emit(&self.emitter, &event) == 0:
        #     error = self._emitter_error()
        #     raise error
        # self._anchor_node(node)
        # self._serialize_node(node, None, None)
        # yaml_document_end_event_initialize(&event, self.document_end_implicit)
        # if yaml_emitter_emit(&self.emitter, &event) == 0:
        #     error = self._emitter_error()
        #     raise error
        # self.serialized_nodes = {}
        # self.anchors = {}
        # self.last_alias_id = 0
        return None

    cdef int _anchor_node(self, object node) except 0:
        # if node in self.anchors:
        #     if self.anchors[node] is None:
        #         self.last_alias_id = self.last_alias_id+1
        #         self.anchors[node] = u"id%03d" % self.last_alias_id
        # else:
        #     self.anchors[node] = None
        #     node_class = node.__class__
        #     if node_class is SequenceNode:
        #         for item in node.value:
        #             self._anchor_node(item)
        #     elif node_class is MappingNode:
        #         for key, value in node.value:
        #             self._anchor_node(key)
        #             self._anchor_node(value)
        # return 1
        return 1

    cdef int _serialize_node(self, object node, object parent, object index) except 0:
        # cdef yaml_event_t event
        # cdef int implicit
        # cdef int plain_implicit
        # cdef int quoted_implicit
        # cdef char *anchor
        # cdef char *tag
        # cdef char *value
        # cdef int length
        # cdef int item_index
        # cdef yaml_scalar_style_t scalar_style
        # cdef yaml_sequence_style_t sequence_style
        # cdef yaml_mapping_style_t mapping_style
        # anchor_object = self.anchors[node]
        # anchor = NULL
        # if anchor_object is not None:
        #     if PyUnicode_CheckExact(anchor_object):
        #         anchor_object = PyUnicode_AsUTF8String(anchor_object)
        #     if not PyString_CheckExact(anchor_object):
        #         if PY_MAJOR_VERSION < 3:
        #             raise TypeError("anchor must be a string")
        #         else:
        #             raise TypeError(u"anchor must be a string")
        #     anchor = PyString_AS_STRING(anchor_object)
        # if node in self.serialized_nodes:
        #     if yaml_alias_event_initialize(&event, anchor) == 0:
        #         raise MemoryError
        #     if yaml_emitter_emit(&self.emitter, &event) == 0:
        #         error = self._emitter_error()
        #         raise error
        # else:
        #     node_class = node.__class__
        #     self.serialized_nodes[node] = True
        #     self.descend_resolver(parent, index)
        #     if node_class is ScalarNode:
        #         plain_implicit = 0
        #         quoted_implicit = 0
        #         tag_object = node.tag
        #         if self.resolve(ScalarNode, node.value, (True, False)) == tag_object:
        #             plain_implicit = 1
        #         if self.resolve(ScalarNode, node.value, (False, True)) == tag_object:
        #             quoted_implicit = 1
        #         tag = NULL
        #         if tag_object is not None:
        #             if PyUnicode_CheckExact(tag_object):
        #                 tag_object = PyUnicode_AsUTF8String(tag_object)
        #             if not PyString_CheckExact(tag_object):
        #                 if PY_MAJOR_VERSION < 3:
        #                     raise TypeError("tag must be a string")
        #                 else:
        #                     raise TypeError(u"tag must be a string")
        #             tag = PyString_AS_STRING(tag_object)
        #         value_object = node.value
        #         if PyUnicode_CheckExact(value_object):
        #             value_object = PyUnicode_AsUTF8String(value_object)
        #         if not PyString_CheckExact(value_object):
        #             if PY_MAJOR_VERSION < 3:
        #                 raise TypeError("value must be a string")
        #             else:
        #                 raise TypeError(u"value must be a string")
        #         value = PyString_AS_STRING(value_object)
        #         length = PyString_GET_SIZE(value_object)
        #         style_object = node.style
        #         scalar_style = YAML_PLAIN_SCALAR_STYLE
        #         if style_object == "'" or style_object == u"'":
        #             scalar_style = YAML_SINGLE_QUOTED_SCALAR_STYLE
        #         elif style_object == "\"" or style_object == u"\"":
        #             scalar_style = YAML_DOUBLE_QUOTED_SCALAR_STYLE
        #         elif style_object == "|" or style_object == u"|":
        #             scalar_style = YAML_LITERAL_SCALAR_STYLE
        #         elif style_object == ">" or style_object == u">":
        #             scalar_style = YAML_FOLDED_SCALAR_STYLE
        #         if yaml_scalar_event_initialize(&event, anchor, tag, value, length,
        #                 plain_implicit, quoted_implicit, scalar_style) == 0:
        #             raise MemoryError
        #         if yaml_emitter_emit(&self.emitter, &event) == 0:
        #             error = self._emitter_error()
        #             raise error
        #     elif node_class is SequenceNode:
        #         implicit = 0
        #         tag_object = node.tag
        #         if self.resolve(SequenceNode, node.value, True) == tag_object:
        #             implicit = 1
        #         tag = NULL
        #         if tag_object is not None:
        #             if PyUnicode_CheckExact(tag_object):
        #                 tag_object = PyUnicode_AsUTF8String(tag_object)
        #             if not PyString_CheckExact(tag_object):
        #                 if PY_MAJOR_VERSION < 3:
        #                     raise TypeError("tag must be a string")
        #                 else:
        #                     raise TypeError(u"tag must be a string")
        #             tag = PyString_AS_STRING(tag_object)
        #         sequence_style = YAML_BLOCK_SEQUENCE_STYLE
        #         if node.flow_style:
        #             sequence_style = YAML_FLOW_SEQUENCE_STYLE
        #         if yaml_sequence_start_event_initialize(&event, anchor, tag,
        #                 implicit, sequence_style) == 0:
        #             raise MemoryError
        #         if yaml_emitter_emit(&self.emitter, &event) == 0:
        #             error = self._emitter_error()
        #             raise error
        #         item_index = 0
        #         for item in node.value:
        #             self._serialize_node(item, node, item_index)
        #             item_index = item_index+1
        #         yaml_sequence_end_event_initialize(&event)
        #         if yaml_emitter_emit(&self.emitter, &event) == 0:
        #             error = self._emitter_error()
        #             raise error
        #     elif node_class is MappingNode:
        #         implicit = 0
        #         tag_object = node.tag
        #         if self.resolve(MappingNode, node.value, True) == tag_object:
        #             implicit = 1
        #         tag = NULL
        #         if tag_object is not None:
        #             if PyUnicode_CheckExact(tag_object):
        #                 tag_object = PyUnicode_AsUTF8String(tag_object)
        #             if not PyString_CheckExact(tag_object):
        #                 if PY_MAJOR_VERSION < 3:
        #                     raise TypeError("tag must be a string")
        #                 else:
        #                     raise TypeError(u"tag must be a string")
        #             tag = PyString_AS_STRING(tag_object)
        #         mapping_style = YAML_BLOCK_MAPPING_STYLE
        #         if node.flow_style:
        #             mapping_style = YAML_FLOW_MAPPING_STYLE
        #         if yaml_mapping_start_event_initialize(&event, anchor, tag,
        #                 implicit, mapping_style) == 0:
        #             raise MemoryError
        #         if yaml_emitter_emit(&self.emitter, &event) == 0:
        #             error = self._emitter_error()
        #             raise error
        #         for item_key, item_value in node.value:
        #             self._serialize_node(item_key, node, None)
        #             self._serialize_node(item_value, node, item_key)
        #         yaml_mapping_end_event_initialize(&event)
        #         if yaml_emitter_emit(&self.emitter, &event) == 0:
        #             error = self._emitter_error()
        #             raise error
        #     self.ascend_resolver()
        # return 1
        return 1

cdef int output_handler(void *data, char *buffer, size_t size) except 0:
    # cdef CEmitter emitter
    # emitter = <CEmitter>data
    # if emitter.dump_unicode == 0:
    #     value = PyString_FromStringAndSize(buffer, size)
    # else:
    #     value = PyUnicode_DecodeUTF8(buffer, size, 'strict')
    # emitter.stream.write(value)
    # return 1
    return 1

