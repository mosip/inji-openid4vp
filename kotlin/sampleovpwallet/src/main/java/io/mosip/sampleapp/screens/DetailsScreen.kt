package io.mosip.sampleapp.screens

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.Icon
import androidx.compose.material.IconButton
import androidx.compose.material.Scaffold
import androidx.compose.material.Text
import androidx.compose.material.TopAppBar
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.navigation.NavHostController
import io.mosip.sampleapp.data.SharedViewModel
import io.mosip.sampleovpwallet.R

@Composable
fun DetailScreen(viewModel: SharedViewModel, navController: NavHostController) {
    val jsonObj = viewModel.vcSelectedForDetails

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.details)) },
                navigationIcon = {
                    IconButton(onClick = { navController.popBackStack() }) {
                        Icon(Icons.Default.ArrowBack, contentDescription = "Back")
                    }
                }
            )
        }
    ) { padding ->
        Box(modifier = Modifier.padding(padding)) {
            if (jsonObj == null) {
                Box(Modifier.fillMaxSize(), Alignment.Center) {
                    Text(stringResource(R.string.no_item_selected))
                }
            } else {
                LazyColumn(
                    Modifier
                        .fillMaxSize()
                        .padding(16.dp)) {
                    items(jsonObj.entrySet().toList()) { (key, value) ->
                        Text("$key: $value", Modifier.padding(4.dp))
                    }
                }
            }
        }
    }
}
