package io.mosip.sampleapp.screens

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.AlertDialog
import androidx.compose.material.Button
import androidx.compose.material.Card
import androidx.compose.material.Checkbox
import androidx.compose.material.Icon
import androidx.compose.material.IconButton
import androidx.compose.material.MaterialTheme
import androidx.compose.material.Text
import androidx.compose.material.TextButton
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.navigation.NavHostController
import io.mosip.sampleapp.Constants
import io.mosip.sampleapp.utils.OpenID4VPManager
import io.mosip.sampleapp.utils.OpenID4VPManager.shareVerifiablePresentation
import io.mosip.sampleapp.Screen
import io.mosip.sampleapp.data.SharedViewModel
import io.mosip.sampleapp.data.VCMetadata
import io.mosip.sampleapp.utils.Utils.getDisplayLabel
import io.mosip.sampleovpwallet.R
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

@Composable
fun MatchingCredentialsScreen(
    sharedViewModel: SharedViewModel,
    navController: NavHostController
) {
    val matchResult by sharedViewModel.matchingResult.collectAsState()
    val selectedItems = remember { mutableStateListOf<Pair<String, VCMetadata>>() }

    var showConsentDialog by remember { mutableStateOf(false) }
    var showDeclineConfirmationDialog by remember { mutableStateOf(false) }
    val coroutineScope = rememberCoroutineScope()

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp)
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.End
        ) {
            IconButton(onClick = {
                coroutineScope.launch(Dispatchers.IO) {
                    OpenID4VPManager.sendErrorToVerifier(Constants.ERR_DECLINED)
                    withContext(Dispatchers.Main) {
                        navController.popBackStack(Screen.Share.route, inclusive = false)
                    }
                }
            }) {
                Icon(Icons.Default.Close, contentDescription = "Close")
            }
        }

        Text(stringResource(R.string.requested_claims, matchResult?.requestedClaims ?: "N/A"), style = MaterialTheme.typography.body1)
        Spacer(modifier = Modifier.height(4.dp))
        Text("Purpose: ${matchResult?.purpose ?: "N/A"}", style = MaterialTheme.typography.body2)
        Spacer(modifier = Modifier.height(16.dp))

        Text(stringResource(R.string.matching_credentials), style = MaterialTheme.typography.h6)
        Spacer(modifier = Modifier.height(8.dp))

        if (matchResult?.matchingVCs?.isNotEmpty() == true) {
            LazyColumn(modifier = Modifier.weight(1f)) {
                matchResult!!.matchingVCs.entries.forEach { entry ->
                    val key = entry.key
                    val vcList = entry.value

                    items(vcList) { vcMetadata ->
                        val vcItem = key to vcMetadata
                        val isSelected = selectedItems.contains(vcItem)


                        Card(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(vertical = 4.dp)
                                .clickable {
                                    if (isSelected) selectedItems.remove(vcItem)
                                    else selectedItems.add(vcItem)
                                }
                        ) {
                            Row(
                                verticalAlignment = Alignment.CenterVertically,
                                modifier = Modifier.padding(8.dp)
                            ) {
                                Checkbox(
                                    checked = isSelected,
                                    onCheckedChange = {
                                        if (it) selectedItems.add(vcItem)
                                        else selectedItems.remove(vcItem)
                                    }
                                )
                                Spacer(modifier = Modifier.width(8.dp))
                                Text(
                                    text = getDisplayLabel(vcMetadata).orEmpty(),
                                    style = MaterialTheme.typography.body1,
                                    maxLines = 1,
                                    overflow = TextOverflow.Ellipsis,
                                    modifier = Modifier.weight(1f)
                                )
                            }
                        }
                    }
                }
            }
        } else {
            Text(stringResource(R.string.no_matching_credentials_found), style = MaterialTheme.typography.body2)
        }

        Spacer(modifier = Modifier.height(16.dp))

        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(vertical = 8.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Button(
                onClick = { showConsentDialog = true },
                enabled = selectedItems.isNotEmpty()
            ) {
                Text("Share")
            }

            Spacer(modifier = Modifier.height(8.dp))

            TextButton(onClick = {
                handleDecline(coroutineScope) {
                    navController.popBackStack(Screen.Share.route, inclusive = false)
                }
            }) {
                Text(stringResource(R.string.reject), color = Color.Red)
            }
        }
    }

    if (showConsentDialog) {
        AlertDialog(
            onDismissRequest = { showConsentDialog = false },
            title = { Text(stringResource(R.string.consent_required)) },
            text = { Text(stringResource(R.string.do_you_want_to_share_selected_credentials)) },
            confirmButton = {
                TextButton(onClick = {
                    showConsentDialog = false
                    coroutineScope.launch {
                        shareVerifiablePresentation(selectedItems)
                    }
                    navController.navigate(Screen.Success.route)
                }) {
                    Text(stringResource(R.string.yes_proceed))
                }
            },
            dismissButton = {
                TextButton(onClick = {
                    showConsentDialog = false
                    showDeclineConfirmationDialog = true
                }) {
                    Text(stringResource(R.string.decline))
                }
            }
        )
    }

    if (showDeclineConfirmationDialog) {
        AlertDialog(
            onDismissRequest = { showDeclineConfirmationDialog = false },
            title = { Text(stringResource(R.string.are_you_sure)) },
            text = { Text(stringResource(R.string.do_you_want_to_go_back_to_scanning)) },
            confirmButton = {
                TextButton(onClick = {
                    handleDecline(coroutineScope) {
                        showDeclineConfirmationDialog = false
                        navController.popBackStack(Screen.Share.route, inclusive = false)
                    }
                }) {
                    Text(stringResource(R.string.yes))
                }
            },
            dismissButton = {
                TextButton(onClick = {
                    showDeclineConfirmationDialog = false
                    showConsentDialog = true
                }) {
                    Text(stringResource(R.string.go_back))
                }
            }
        )
    }
}


fun handleDecline(
    coroutineScope: CoroutineScope,
    onDeclineConfirmed: () -> Unit
) {
    coroutineScope.launch(Dispatchers.IO) {
        OpenID4VPManager.sendErrorToVerifier(Constants.ERR_DECLINED)
        withContext(Dispatchers.Main) {
            onDeclineConfirmed()
        }
    }
}


