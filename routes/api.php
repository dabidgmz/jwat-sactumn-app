<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

use App\Http\Controllers\AuthController;
/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| is assigned the "api" middleware group. Enjoy building your API!
|
*/




// Rutas de autenticación JWT


// Rutas de autenticación Sanctum
Route::post('loginv2', [AuthController::class, 'loginv2']);
Route::post('registerv2', [AuthController::class, 'registerv2']);