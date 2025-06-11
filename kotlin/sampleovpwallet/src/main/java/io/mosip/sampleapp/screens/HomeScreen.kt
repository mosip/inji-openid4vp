package io.mosip.sampleapp.screens

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.material.Card
import androidx.compose.material.DropdownMenu
import androidx.compose.material.DropdownMenuItem
import androidx.compose.material.ExtendedFloatingActionButton
import androidx.compose.material.FloatingActionButton
import androidx.compose.material.Icon
import androidx.compose.material.IconButton
import androidx.compose.material.MaterialTheme
import androidx.compose.material.Text
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.navigation.NavHostController
import io.mosip.sampleapp.Screen
import io.mosip.sampleapp.data.SharedViewModel
import io.mosip.sampleapp.VCMetadata
import io.mosip.sampleapp.utils.Utils.getDisplayLabel
import io.mosip.sampleovpwallet.R

@Composable
fun HomeScreen(navController: NavHostController, viewModel: SharedViewModel) {
    var showFabMenu by remember { mutableStateOf(false) }
    var expandedRowIndex by remember { mutableStateOf<Int?>(null) }

    LaunchedEffect(Unit) {
        viewModel.loadAllProperties()
        viewModel.loadVerifiers()
    }

    val downloadedVcs = viewModel.downloadedVcs

    Box(Modifier.fillMaxSize()) {
        if (downloadedVcs.isEmpty()) {
            Box(Modifier.fillMaxSize(), Alignment.Center) {
                Text(stringResource(R.string.no_vcs_downloaded_tap_icon_to_download_vcs))
            }
        } else {
            LazyColumn(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(8.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                itemsIndexed(downloadedVcs) { index, jsonObj ->
                    Card(
                        elevation = 4.dp,
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable {
                                viewModel.displayVcDetails(jsonObj.vc)
                                navController.navigate(Screen.Details.route)
                            }
                    ) {
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(16.dp),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.SpaceBetween
                        ) {

                            Text(
                                text = getDisplayLabel(jsonObj).orEmpty(),
                                style = MaterialTheme.typography.body1
                            )

                            Box {
                                IconButton(onClick = {
                                    expandedRowIndex =
                                        if (expandedRowIndex == index) null else index
                                }) {
                                    Icon(Icons.Default.MoreVert, contentDescription = "Options")
                                }

                                DropdownMenu(
                                    expanded = expandedRowIndex == index,
                                    onDismissRequest = { expandedRowIndex = null }
                                ) {
                                    DropdownMenuItem(onClick = {
                                        viewModel.removeVC(index)
                                        expandedRowIndex = null
                                    }) {
                                        Text(stringResource(R.string.delete))
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        Box(
            Modifier
                .align(Alignment.BottomEnd)
                .padding(16.dp)
        ) {
            Column(horizontalAlignment = Alignment.End) {
                if (showFabMenu) {
                    viewModel.issuersList.forEach { (label, credential) ->
                        ExtendedFloatingActionButton(
                            text = { Text(label) },
                            onClick = {
                                val copiedVc = credential.vc.deepCopy().asJsonObject
                                val format = credential.format
                                viewModel.addVC(VCMetadata(format, copiedVc, credential.keyType, credential.rawCBORData))
                                showFabMenu = false
                            },
                            modifier = Modifier.padding(bottom = 8.dp)
                        )
                    }
                }
                FloatingActionButton(onClick = { showFabMenu = !showFabMenu }) {
                    Icon(Icons.Default.Add, contentDescription = "Add")
                }
            }
        }
    }
}






