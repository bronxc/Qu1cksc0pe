"""Fake Word Document object -- only as deep as needed to expose recovered
ActiveX control values (see activex_extractor.py) as named properties.
Everything else degrades through the normal ComObject fallback, same as
any other unmodeled member."""

from vba_emulator.com_objects import ComObject, safe_str
from vba_emulator.values import VBEmpty


class ActiveXControlValue(ComObject):
    progid = "MSForms.Control"

    def __init__(self, session, interp, value):
        super().__init__(session, interp)
        self._value = value

    def p_value(self):
        return self._value

    def p_text(self):
        return self._value

    def p_caption(self):
        return self._value


class UserFormObject(ComObject):
    """Predeclared VBA UserForm instance.

    UserForms are class modules whose default instance is reachable by the
    module name (for example ``UserForm1.box5.Text``) without ``New``.  The
    form/control binary is not always available -- notably for a standalone
    extracted ``.vba`` source file -- so an unknown control intentionally
    returns an empty control value instead of aborting the rest of the macro.
    When the Office container supplied recovered ActiveX values, the same
    case-insensitive mapping is reused here.
    """

    progid = "MSForms.UserForm"

    def __init__(self, session, interp, name, controls=None):
        super().__init__(session, interp)
        self.name = name
        self._controls = {k.lower(): v for k, v in (controls or {}).items()}

    def get_prop(self, name):
        key = name.lower()
        if key in ("name", "caption"):
            return self.name
        return ActiveXControlValue(
            self.session, self.interp, self._controls.get(key, ""))

    def m_show(self, args):
        return VBEmpty

    def m_hide(self, args):
        return VBEmpty


class DocumentPropertyObject(ComObject):
    """One entry of Application.CustomDocumentProperties/
    BuiltInDocumentProperties -- see doc_properties_extractor.py for where
    real values are recovered from docProps/custom.xml."""

    progid = "Office.DocumentProperty"

    def __init__(self, session, interp, name, value):
        super().__init__(session, interp)
        self._name = name
        self._value = value

    def p_value(self):
        return self._value

    def p_name(self):
        return self._name


class CustomXMLNode(ComObject):
    """Result of CustomXMLPart.SelectSingleNode(xpath) -- xpath itself
    isn't evaluated (the overwhelming majority of real samples just do
    `.SelectSingleNode("/").Text` to grab the whole part's content), so
    every call returns the same node wrapping that content."""

    progid = "MSXML2.IXMLDOMNode"

    def __init__(self, session, interp, text):
        super().__init__(session, interp)
        self._text = text

    def p_text(self):
        return self._text


class CustomXMLPart(ComObject):
    """See custom_xml_extractor.py for where real values are recovered
    from customXml/itemN.xml."""

    progid = "Office.CustomXMLPart"

    def __init__(self, session, interp, text):
        super().__init__(session, interp)
        self._text = text

    def m_selectsinglenode(self, args):
        return CustomXMLNode(self.session, self.interp, self._text)

    def p_text(self):
        return self._text


class WordDocumentObject(ComObject):
    progid = "Word.Document"

    def __init__(self, session, interp, controls=None, custom_properties=None, custom_xml_parts=None):
        super().__init__(session, interp)
        self._controls = {k.lower(): v for k, v in (controls or {}).items()}
        # {lowercased_name: (real_name, value)} -- real_name preserves the
        # original casing for .Name, lookups stay case-insensitive like
        # real VBA collection indexing.
        self._custom_properties = {k.lower(): (k, v) for k, v in (custom_properties or {}).items()}
        # Keyed by namespace URI exactly as CustomXMLParts(uri) indexes --
        # real Word namespace URIs are case-sensitive, so unlike the two
        # dicts above this one is not lowercased.
        self._custom_xml_parts = custom_xml_parts or {}

    def get_prop(self, name):
        key = name.lower()
        if key in self._controls:
            return ActiveXControlValue(self.session, self.interp, self._controls[key])
        return super().get_prop(name)

    def m_customdocumentproperties(self, args):
        name = safe_str(args[0]) if args else ""
        recovered = name.lower() in self._custom_properties
        real_name, value = self._custom_properties.get(name.lower(), (name, ""))
        self.ioc.emit("doc_property_access", api="CustomDocumentProperties",
                       name=name, recovered=recovered)
        return DocumentPropertyObject(self.session, self.interp, real_name, value)

    def m_builtindocumentproperties(self, args):
        return self.m_customdocumentproperties(args)

    def m_customxmlparts(self, args):
        uri = safe_str(args[0]) if args else ""
        text = self._custom_xml_parts.get(uri, "")
        self.ioc.emit("doc_property_access", api="CustomXMLParts",
                       name=uri, recovered=uri in self._custom_xml_parts)
        return CustomXMLPart(self.session, self.interp, text)

    def p_fullname(self):
        return self.session.env_vars.get("USERPROFILE", "C:\\Users\\User") + "\\Desktop\\Document1.docm"

    def p_name(self):
        return "Document1.docm"

    def p_path(self):
        return self.session.env_vars.get("USERPROFILE", "C:\\Users\\User") + "\\Desktop"


class ApplicationObject(ComObject):
    """Fake Word/Excel `Application` object. Macros commonly reach the
    active document/workbook two ways -- the bare ambient global
    (`ActiveDocument`) or through `Application.ActiveDocument` -- and both
    must resolve to the *same* fake document object. Without this, the
    generic ComObject fallback returns Empty for the unmodeled
    `.ActiveDocument` property, and a chained `.FullName` off that Empty
    hard-crashes the whole emulation on a `Application.ActiveDocument.
    FullName`-shaped one-liner (a common real-sample idiom) instead of
    degrading gracefully like the direct-reference form already does."""

    progid = "Application"

    _AMBIENT_NAMES = (
        "activedocument", "thisdocument", "activeworkbook", "thisworkbook",
        "activesheet", "selection", "sheets", "worksheets",
    )

    def get_prop(self, name):
        key = name.lower()
        if key in self._AMBIENT_NAMES and self.interp is not None:
            obj = self.interp.global_env.vars.get(key)
            if obj is not None:
                return obj
        return super().get_prop(name)

    def m_range(self, args):
        """Application.Range(...) delegates to the active worksheet."""
        from vba_emulator.excel import ambient_range
        return ambient_range(self.interp, args)

    def m_cells(self, args):
        """Application.Cells(row, column) delegates to the active sheet."""
        from vba_emulator.excel import ambient_cells
        return ambient_cells(self.interp, args)

    def m_sheets(self, args):
        sheets = self.interp.global_env.vars.get("sheets")
        return sheets.default_index(args) if sheets is not None else super().invoke("Sheets", args)

    def m_worksheets(self, args):
        return self.m_sheets(args)

    def m_quit(self, args):
        # Closing the real Office host has no side effect in the sandbox;
        # treat it as a successful no-op so a common end-of-macro cleanup
        # call does not appear as an unmodeled COM gap.
        return VBEmpty
