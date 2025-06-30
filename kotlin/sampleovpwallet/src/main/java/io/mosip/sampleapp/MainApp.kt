package io.mosip.sampleapp

import androidx.compose.foundation.layout.padding
import androidx.compose.material.AlertDialog
import androidx.compose.material.BottomNavigation
import androidx.compose.material.BottomNavigationItem
import androidx.compose.material.Button
import androidx.compose.material.Icon
import androidx.compose.material.Scaffold
import androidx.compose.material.Text
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.filled.Share
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import io.mosip.sampleapp.data.SharedViewModel
import io.mosip.sampleapp.screens.DetailScreen
import io.mosip.sampleapp.screens.HomeScreen
import io.mosip.sampleapp.screens.MatchingCredentialsScreen
import io.mosip.sampleapp.screens.ShareScreen
import io.mosip.sampleapp.screens.SuccessScreen
import io.mosip.sampleovpwallet.R

sealed class Screen(val route: String) {
    object Home : Screen("home")
    object Details : Screen("details")
    object Share : Screen("share")
    object MatchingVcs : Screen("matching_vcs")
    object Success : Screen("success")
}



@Composable
fun MainApp() {
    val navController = rememberNavController()
    val sharedViewModel = remember { SharedViewModel() }
    var showNoVcDialog by remember { mutableStateOf(false) }

    val currentBackStackEntry by navController.currentBackStackEntryAsState()
    val currentRoute = currentBackStackEntry?.destination?.route

    Scaffold(
        bottomBar = {
            if (currentRoute != Screen.Details.route && currentRoute != Screen.MatchingVcs.route && currentRoute != Screen.Success.route) {
                BottomNavigation {
                    BottomNavigationItem(
                        icon = { Icon(Icons.Default.Home, contentDescription = null) },
                        label = { Text(stringResource(R.string.home)) },
                        selected = currentRoute == Screen.Home.route,
                        onClick = {
                            navController.navigate(Screen.Home.route) {
                                popUpTo(Screen.Home.route) { inclusive = true }
                            }
                        }
                    )
                    BottomNavigationItem(
                        icon = { Icon(Icons.Default.Share, contentDescription = null) },
                        label = { Text(stringResource(R.string.share)) },
                        selected = currentRoute == Screen.Share.route,
                        onClick = {
                            if (sharedViewModel.downloadedVcs.isEmpty()) {
                                showNoVcDialog = true
                            } else {
                                navController.navigate(Screen.Share.route) {
                                    launchSingleTop = true
                                }
                            }
                        }
                    )
                }
            }
        }
    ) { innerPadding ->
        if (showNoVcDialog) {
            AlertDialog(
                onDismissRequest = { showNoVcDialog = false },
                title = { Text(stringResource(R.string.no_vc_to_share)) },
                text = { Text(stringResource(R.string.no_verifiable_credential_found_to_share)) },
                confirmButton = {
                    Button(onClick = { showNoVcDialog = false }) {
                        Text(stringResource(R.string.ok))
                    }
                }
            )
        }

        NavHost(
            navController,
            startDestination = Screen.Home.route,
            modifier = Modifier.padding(innerPadding)
        ) {
            composable(Screen.Home.route) {
                HomeScreen(navController, sharedViewModel)
            }
            composable(Screen.Share.route) {
                ShareScreen(navController, sharedViewModel)
            }
            composable(Screen.MatchingVcs.route) {
                MatchingCredentialsScreen(sharedViewModel, navController)
            }
            composable(Screen.Details.route) {
                DetailScreen(sharedViewModel, navController)
            }
            composable(Screen.Success.route) {
                SuccessScreen(navController)
            }
        }
    }
}





