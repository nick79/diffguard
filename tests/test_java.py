"""Tests for Java language support."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from diffguard.ast import (
    Language,
    detect_language,
    extract_imports,
    find_used_symbols,
    is_first_party,
    parse_file,
    resolve_symbol_definition,
)
from diffguard.ast.java import _extract_package, clear_build_config_cache
from diffguard.ast.python import Import
from diffguard.ast.scope import find_enclosing_scope
from diffguard.config import DiffguardConfig
from diffguard.exclusions import is_generated_file
from diffguard.git import DiffFile, DiffHunk
from diffguard.pipeline import _filter_analyzable_files

if TYPE_CHECKING:
    from tree_sitter import Tree


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _parse_java(source: str) -> Tree:
    """Parse Java source and return a tree-sitter Tree."""
    tree = parse_file(source, Language.JAVA)
    assert tree is not None
    return tree


def _make_diff_file(path: str) -> DiffFile:
    return DiffFile(
        old_path=path,
        new_path=path,
        hunks=[DiffHunk(old_start=1, old_count=1, new_start=1, new_count=1, lines=[("+", "x")])],
        is_new_file=False,
        is_deleted=False,
        is_binary=False,
    )


# ---------------------------------------------------------------------------
# Test fixtures
# ---------------------------------------------------------------------------

JAVA_CLASS = """\
package com.example;

import java.util.List;
import java.util.Map;
import com.internal.Helper;
import static com.example.Utils.formatString;

public class MyService {
    private List<String> items;

    public MyService(List<String> items) {
        this.items = items;
    }

    public void process(String input) {
        Helper.validate(input);
    }

    public static void main(String[] args) {
        System.out.println("Hello");
    }
}
"""

JAVA_INTERFACE = """\
package com.example;

public interface Repository<T> {
    T findById(Long id);
    List<T> findAll();
    void save(T entity);
}
"""

JAVA_ENUM = """\
package com.example;

public enum Status {
    PENDING("Pending"),
    ACTIVE("Active"),
    COMPLETED("Completed");

    private final String displayName;

    Status(String displayName) {
        this.displayName = displayName;
    }

    public String getDisplayName() {
        return displayName;
    }
}
"""

JAVA_ANNOTATIONS = """\
package com.example;

import org.springframework.stereotype.Service;
import org.springframework.beans.factory.annotation.Autowired;

@Service
public class UserService {
    @Autowired
    private UserRepository repository;

    @Override
    public String toString() {
        return "UserService";
    }
}
"""

JAVA_LAMBDA = """\
package com.example;

import java.util.List;

public class Processor {
    public void processAll(List<String> items) {
        items.forEach(item -> {
            System.out.println(item);
        });
    }
}
"""

JAVA_GENERATED = """\
package com.example;

import javax.annotation.processing.Generated;

@Generated("com.example.processor")
public class GeneratedDto {
    private String field;
}
"""

JAVA_INNER_CLASS = """\
package com.example;

public class Outer {
    public class Inner {
        public void innerMethod() {
            System.out.println("inner");
        }
    }

    public void outerMethod() {
        System.out.println("outer");
    }
}
"""


# ---------------------------------------------------------------------------
# Language Detection
# ---------------------------------------------------------------------------


class TestJavaLanguageDetection:
    def test_detect_java_extension(self) -> None:
        assert detect_language("src/main/java/com/example/MyClass.java") == Language.JAVA

    def test_detect_java_simple(self) -> None:
        assert detect_language("MyClass.java") == Language.JAVA

    def test_detect_non_java(self) -> None:
        assert detect_language("src/main.py") != Language.JAVA

    def test_parse_valid_java(self) -> None:
        tree = _parse_java(JAVA_CLASS)
        assert tree is not None
        assert tree.root_node.type == "program"


# ---------------------------------------------------------------------------
# Scope Detection
# ---------------------------------------------------------------------------


class TestJavaScopeDetection:
    def test_class_scope(self) -> None:
        tree = _parse_java(JAVA_CLASS)
        # Line inside class body but not in a method (line 9: `private List<String> items;`)
        scope = find_enclosing_scope(tree, 9, Language.JAVA)
        assert scope is not None
        assert scope.type == "class"
        assert scope.name == "MyService"

    def test_method_scope(self) -> None:
        tree = _parse_java(JAVA_CLASS)
        # Line inside `process` method body (line 17: `Helper.validate(input);`)
        scope = find_enclosing_scope(tree, 17, Language.JAVA)
        assert scope is not None
        assert scope.type == "method"
        assert scope.name == "process"

    def test_constructor_scope(self) -> None:
        tree = _parse_java(JAVA_CLASS)
        # Line inside constructor (line 12: `this.items = items;`)
        scope = find_enclosing_scope(tree, 12, Language.JAVA)
        assert scope is not None
        assert scope.type == "constructor"
        assert scope.name == "MyService"

    def test_static_method_scope(self) -> None:
        tree = _parse_java(JAVA_CLASS)
        # Line inside `main` method (line 21: `System.out.println...`)
        scope = find_enclosing_scope(tree, 21, Language.JAVA)
        assert scope is not None
        assert scope.type == "method"
        assert scope.name == "main"

    def test_interface_scope(self) -> None:
        tree = _parse_java(JAVA_INTERFACE)
        # Line 3: `public interface Repository<T> {` — inside interface declaration
        scope = find_enclosing_scope(tree, 3, Language.JAVA)
        assert scope is not None
        assert scope.type == "interface"
        assert scope.name == "Repository"

    def test_interface_method_scope(self) -> None:
        tree = _parse_java(JAVA_INTERFACE)
        # Line 4: `T findById(Long id);` — inside method within interface
        scope = find_enclosing_scope(tree, 4, Language.JAVA)
        assert scope is not None
        assert scope.type == "method"
        assert scope.name == "findById"

    def test_enum_scope(self) -> None:
        tree = _parse_java(JAVA_ENUM)
        # Line inside enum body (line 4: `PENDING("Pending"),`)
        scope = find_enclosing_scope(tree, 4, Language.JAVA)
        assert scope is not None
        assert scope.type == "enum"
        assert scope.name == "Status"

    def test_enum_method_scope(self) -> None:
        tree = _parse_java(JAVA_ENUM)
        # Line inside getDisplayName method (line 16: `return displayName;`)
        scope = find_enclosing_scope(tree, 16, Language.JAVA)
        assert scope is not None
        assert scope.type == "method"
        assert scope.name == "getDisplayName"

    def test_lambda_scope(self) -> None:
        tree = _parse_java(JAVA_LAMBDA)
        # Line inside lambda body (line 8: `System.out.println(item);`)
        scope = find_enclosing_scope(tree, 8, Language.JAVA)
        assert scope is not None
        assert scope.type == "lambda"
        assert scope.name == "<lambda>"

    def test_inner_class_scope(self) -> None:
        tree = _parse_java(JAVA_INNER_CLASS)
        # Line inside Inner class method (line 6: `System.out.println("inner");`)
        scope = find_enclosing_scope(tree, 6, Language.JAVA)
        assert scope is not None
        assert scope.type == "method"
        assert scope.name == "innerMethod"

    def test_annotation_included_in_method_scope(self) -> None:
        tree = _parse_java(JAVA_ANNOTATIONS)
        # The @Override annotated method — line 11 is `@Override`, line 12 is `public String toString()`
        scope = find_enclosing_scope(tree, 13, Language.JAVA)
        assert scope is not None
        assert scope.type == "method"
        assert scope.name == "toString"
        # The method_declaration includes the @Override annotation
        assert scope.start_line <= 11

    def test_no_scope_at_package_level(self) -> None:
        tree = _parse_java(JAVA_CLASS)
        # Line 1: `package com.example;`
        scope = find_enclosing_scope(tree, 1, Language.JAVA)
        assert scope is None


# ---------------------------------------------------------------------------
# Import Extraction
# ---------------------------------------------------------------------------


class TestJavaImportExtraction:
    def test_single_import(self) -> None:
        tree = _parse_java(JAVA_CLASS)
        imports = extract_imports(tree, Language.JAVA)
        modules = [imp.module for imp in imports]
        assert "java.util.List" in modules

    def test_multiple_imports(self) -> None:
        tree = _parse_java(JAVA_CLASS)
        imports = extract_imports(tree, Language.JAVA)
        assert len(imports) == 4

    def test_static_import(self) -> None:
        tree = _parse_java(JAVA_CLASS)
        imports = extract_imports(tree, Language.JAVA)
        static_imports = [imp for imp in imports if imp.names and "formatString" in imp.names]
        assert len(static_imports) == 1
        assert static_imports[0].module == "com.example.Utils"

    def test_wildcard_import(self) -> None:
        source = """\
import java.util.*;
"""
        tree = _parse_java(source)
        imports = extract_imports(tree, Language.JAVA)
        assert len(imports) == 1
        assert imports[0].module == "java.util"
        assert imports[0].is_star is True

    def test_static_wildcard_import(self) -> None:
        source = """\
import static org.junit.Assert.*;
"""
        tree = _parse_java(source)
        imports = extract_imports(tree, Language.JAVA)
        assert len(imports) == 1
        assert imports[0].is_star is True

    def test_import_names_extracted(self) -> None:
        tree = _parse_java(JAVA_CLASS)
        imports = extract_imports(tree, Language.JAVA)
        list_import = [imp for imp in imports if "List" in (imp.names or [])]
        assert len(list_import) == 1
        assert list_import[0].module == "java.util.List"


# ---------------------------------------------------------------------------
# Symbol Usage Detection
# ---------------------------------------------------------------------------


class TestJavaSymbolUsage:
    def test_used_symbols_in_method(self) -> None:
        tree = _parse_java(JAVA_CLASS)
        # `process` method lines 16-18: `Helper.validate(input);`
        symbols = find_used_symbols(tree, 16, 18, Language.JAVA)
        assert "Helper" in symbols

    def test_excludes_builtins(self) -> None:
        tree = _parse_java(JAVA_CLASS)
        symbols = find_used_symbols(tree, 20, 22, Language.JAVA, exclude_builtins=True)
        # System is a builtin, should be excluded
        assert "System" not in symbols

    def test_local_definitions_excluded(self) -> None:
        tree = _parse_java(JAVA_CLASS)
        # Constructor: `public MyService(List<String> items) { this.items = items; }`
        symbols = find_used_symbols(tree, 11, 13, Language.JAVA)
        # `items` is defined as a parameter, should not appear as used
        assert "items" not in symbols

    def test_lambda_parameter_defined(self) -> None:
        tree = _parse_java(JAVA_LAMBDA)
        # Lambda body: `item -> { System.out.println(item); }`
        symbols = find_used_symbols(tree, 7, 9, Language.JAVA)
        # `item` is defined as lambda parameter
        assert "item" not in symbols


# ---------------------------------------------------------------------------
# First-Party Detection
# ---------------------------------------------------------------------------


class TestJavaFirstPartyDetection:
    def test_stdlib_not_first_party(self) -> None:
        root = Path("/project")
        assert is_first_party("java.util.List", root, [], Language.JAVA) is False

    def test_javax_not_first_party(self) -> None:
        root = Path("/project")
        assert is_first_party("javax.crypto.Cipher", root, [], Language.JAVA) is False

    def test_first_party_with_pom_xml(self, tmp_path: Path) -> None:
        clear_build_config_cache()
        pom_content = """<?xml version="1.0" encoding="UTF-8"?>
<project>
    <groupId>com.mycompany</groupId>
    <artifactId>myapp</artifactId>
</project>"""
        (tmp_path / "pom.xml").write_text(pom_content)
        assert is_first_party("com.mycompany.internal.Helper", tmp_path, [], Language.JAVA) is True

    def test_third_party_with_pom_xml(self, tmp_path: Path) -> None:
        clear_build_config_cache()
        pom_content = """<?xml version="1.0" encoding="UTF-8"?>
<project>
    <groupId>com.mycompany</groupId>
</project>"""
        (tmp_path / "pom.xml").write_text(pom_content)
        assert is_first_party("org.apache.commons.lang3.StringUtils", tmp_path, [], Language.JAVA) is False

    def test_first_party_with_build_gradle(self, tmp_path: Path) -> None:
        clear_build_config_cache()
        (tmp_path / "build.gradle").write_text("group = 'com.mycompany'\nversion = '1.0'")
        assert is_first_party("com.mycompany.service.UserService", tmp_path, [], Language.JAVA) is True

    def test_first_party_with_build_gradle_kts(self, tmp_path: Path) -> None:
        clear_build_config_cache()
        (tmp_path / "build.gradle.kts").write_text('group = "com.mycompany"\nversion = "1.0"')
        assert is_first_party("com.mycompany.api.Controller", tmp_path, [], Language.JAVA) is True

    def test_first_party_by_directory_structure(self, tmp_path: Path) -> None:
        clear_build_config_cache()
        java_src = tmp_path / "src" / "main" / "java" / "com" / "mycompany"
        java_src.mkdir(parents=True)
        (java_src / "App.java").write_text("package com.mycompany;")
        assert is_first_party("com.mycompany.App", tmp_path, [], Language.JAVA) is True

    def test_first_party_resolves_to_file(self, tmp_path: Path) -> None:
        clear_build_config_cache()
        src_dir = tmp_path / "src" / "main" / "java" / "com" / "example"
        src_dir.mkdir(parents=True)
        (src_dir / "Helper.java").write_text("package com.example;")
        assert is_first_party("com.example.Helper", tmp_path, [], Language.JAVA) is True


# ---------------------------------------------------------------------------
# Symbol Resolution
# ---------------------------------------------------------------------------


class TestJavaSymbolResolution:
    def test_resolve_import_to_file(self, tmp_path: Path) -> None:
        src_dir = tmp_path / "src" / "main" / "java" / "com" / "example" / "utils"
        src_dir.mkdir(parents=True)
        helper_file = src_dir / "Helper.java"
        helper_file.write_text("package com.example.utils;")

        imports = [Import(module="com.example.utils.Helper", names=["Helper"])]
        result = resolve_symbol_definition("Helper", imports, tmp_path, None, Language.JAVA)
        assert result is not None
        assert result == helper_file

    def test_resolve_unresolvable_returns_none(self, tmp_path: Path) -> None:
        imports = [Import(module="com.unknown.Helper", names=["Helper"])]
        result = resolve_symbol_definition("Helper", imports, tmp_path, None, Language.JAVA)
        assert result is None

    def test_resolve_no_matching_import(self, tmp_path: Path) -> None:
        imports = [Import(module="com.example.Other", names=["Other"])]
        result = resolve_symbol_definition("Helper", imports, tmp_path, None, Language.JAVA)
        assert result is None


# ---------------------------------------------------------------------------
# Vendor/Build Output Path Filtering
# ---------------------------------------------------------------------------


class TestJavaVendorPathFiltering:
    def test_skip_maven_target(self) -> None:
        config = DiffguardConfig()
        files = [_make_diff_file("target/classes/com/example/MyClass.java")]
        result = _filter_analyzable_files(files, config)
        assert len(result) == 0

    def test_skip_gradle_build(self) -> None:
        config = DiffguardConfig()
        files = [_make_diff_file("build/generated/sources/MyClass.java")]
        result = _filter_analyzable_files(files, config)
        assert len(result) == 0

    def test_skip_gradle_cache(self) -> None:
        config = DiffguardConfig()
        files = [_make_diff_file(".gradle/caches/some/MyClass.java")]
        result = _filter_analyzable_files(files, config)
        assert len(result) == 0

    def test_normal_java_file_kept(self) -> None:
        config = DiffguardConfig()
        files = [_make_diff_file("src/main/java/com/example/MyClass.java")]
        result = _filter_analyzable_files(files, config)
        assert len(result) == 1


# ---------------------------------------------------------------------------
# Generated File Detection
# ---------------------------------------------------------------------------


class TestJavaGeneratedFileDetection:
    def test_skip_generated_sources_path(self) -> None:
        assert is_generated_file("target/generated-sources/annotations/com/example/Gen.java", [], Language.JAVA) is True

    def test_skip_apt_generated_path(self) -> None:
        assert is_generated_file("build/apt_generated/com/example/Gen.java", [], Language.JAVA) is True

    def test_skip_generated_annotation(self) -> None:
        lines = JAVA_GENERATED.splitlines()
        assert is_generated_file("src/main/java/com/example/GeneratedDto.java", lines, Language.JAVA) is True

    def test_normal_java_not_generated(self) -> None:
        lines = JAVA_CLASS.splitlines()
        assert is_generated_file("src/main/java/com/example/MyService.java", lines, Language.JAVA) is False

    def test_generated_path_segment(self) -> None:
        assert is_generated_file("some/generated/path/File.java", [], Language.JAVA) is True


# ---------------------------------------------------------------------------
# Parsing Features
# ---------------------------------------------------------------------------


class TestJavaParsingFeatures:
    def test_parse_annotations(self) -> None:
        tree = _parse_java(JAVA_ANNOTATIONS)
        assert tree is not None
        assert not tree.root_node.has_error

    def test_parse_generics(self) -> None:
        tree = _parse_java(JAVA_INTERFACE)
        assert tree is not None
        assert not tree.root_node.has_error

    def test_parse_enum(self) -> None:
        tree = _parse_java(JAVA_ENUM)
        assert tree is not None
        assert not tree.root_node.has_error

    def test_parse_lambda(self) -> None:
        tree = _parse_java(JAVA_LAMBDA)
        assert tree is not None
        assert not tree.root_node.has_error

    def test_parse_try_with_resources(self) -> None:
        source = """\
import java.io.*;

public class FileReader {
    public String read(String path) throws IOException {
        try (BufferedReader br = new BufferedReader(new java.io.FileReader(path))) {
            return br.readLine();
        }
    }
}
"""
        tree = _parse_java(source)
        assert tree is not None

    def test_package_declaration_extracted(self) -> None:
        tree = _parse_java(JAVA_CLASS)
        pkg = _extract_package(tree)
        assert pkg == "com.example"

    def test_parse_inner_class(self) -> None:
        tree = _parse_java(JAVA_INNER_CLASS)
        assert tree is not None
        assert not tree.root_node.has_error
