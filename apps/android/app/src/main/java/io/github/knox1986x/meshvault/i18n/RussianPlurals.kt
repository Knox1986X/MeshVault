package io.github.knox1986x.meshvault.i18n

/**
 * Russian grammatical pluralization helper following East Slavic rules (1, 2-4, 5-20).
 */
object RussianPlurals {

    fun format(count: Long, one: String, few: String, many: String): String {
        val absCount = kotlin.math.abs(count)
        val mod100 = (absCount % 100).toInt()
        val mod10 = (absCount % 10).toInt()
        val form = when {
            mod100 in 11..19 -> many
            mod10 == 1 -> one
            mod10 in 2..4 -> few
            else -> many
        }
        return "$count $form"
    }

    fun foldersCount(count: Long): String = format(count, "папка", "папки", "папок")

    fun subfoldersCount(count: Long): String = format(count, "подпапка", "подпапки", "подпапок")

    fun photosCount(count: Long): String = format(count, "фотография", "фотографии", "фотографий")

    fun filesCount(count: Long): String = format(count, "файл", "файла", "файлов")

    fun importSummaryRu(folders: Long, photos: Long): String {
        val mod100 = (kotlin.math.abs(folders) % 100).toInt()
        val mod10 = (kotlin.math.abs(folders) % 10).toInt()
        val verb = if (mod10 == 1 && mod100 != 11) "импортирована" else "импортировано"
        return "$verb ${foldersCount(folders)}, ${photosCount(photos)}"
    }
}
