package io.github.knox1986x.meshvault.i18n

import org.junit.Assert.assertEquals
import org.junit.Test

class RussianPluralsTest {

    @Test
    fun formatsFilesCountInRussian() {
        assertEquals("0 файлов", RussianPlurals.filesCount(0))
        assertEquals("1 файл", RussianPlurals.filesCount(1))
        assertEquals("2 файла", RussianPlurals.filesCount(2))
        assertEquals("5 файлов", RussianPlurals.filesCount(5))
        assertEquals("11 файлов", RussianPlurals.filesCount(11))
        assertEquals("14 файлов", RussianPlurals.filesCount(14))
        assertEquals("21 файл", RussianPlurals.filesCount(21))
        assertEquals("24 файла", RussianPlurals.filesCount(24))
        assertEquals("102 файла", RussianPlurals.filesCount(102))
        assertEquals("112 файлов", RussianPlurals.filesCount(112))
    }

    @Test
    fun formatsFoldersAndSubfoldersInRussian() {
        assertEquals("1 папка", RussianPlurals.foldersCount(1))
        assertEquals("3 папки", RussianPlurals.foldersCount(3))
        assertEquals("12 папок", RussianPlurals.foldersCount(12))
        assertEquals("1 подпапка", RussianPlurals.subfoldersCount(1))
        assertEquals("4 подпапки", RussianPlurals.subfoldersCount(4))
        assertEquals("19 подпапок", RussianPlurals.subfoldersCount(19))
    }
}
