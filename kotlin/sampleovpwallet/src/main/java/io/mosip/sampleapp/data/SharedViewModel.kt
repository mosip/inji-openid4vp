package io.mosip.sampleapp.data

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.google.gson.JsonObject
import io.mosip.sampleapp.utils.MatchingResult
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch

class SharedViewModel : ViewModel() {

    private val _downloadedVcs = mutableStateListOf<VCMetadata>()
    val downloadedVcs: List<VCMetadata> get() = _downloadedVcs

    fun addVC(item: VCMetadata) {
        _downloadedVcs.add(item)
    }

    fun removeVC(index: Int) {
        _downloadedVcs.removeAt(index)
    }

    var scannedQr: String? by mutableStateOf(null)
        private set

    fun updateScannedQr(data: String) {
        scannedQr = data
    }

    private val _matchingResult = MutableStateFlow<MatchingResult?>(null)
    val matchingResult: StateFlow<MatchingResult?> = _matchingResult

    fun storeMatchResult(result: MatchingResult) {
        viewModelScope.launch {
            _matchingResult.value = result
        }
    }

    var vcSelectedForDetails : JsonObject? = null
        private set

    fun displayVcDetails(item: JsonObject) {
        vcSelectedForDetails = item
    }

}


