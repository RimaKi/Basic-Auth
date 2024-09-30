<?php

namespace App\Http\Requests\Auth;

use Illuminate\Auth\Access\AuthorizationException;
use Illuminate\Foundation\Http\FormRequest;

class ChangePasswordRequest extends FormRequest
{
    /**
     * Determine if the user is authorized to make this request.
     */
    public function authorize(): bool
    {
        if (!(password_verify($this->old_password, \auth()->user()->password))) {
            throw new AuthorizationException('wrong ola password');
        }
        return true;
    }

    /**
     * Get the validation rules that apply to the request.
     *
     * @return array<string, \Illuminate\Contracts\Validation\ValidationRule|array<mixed>|string>
     */
    public function rules(): array
    {
        return [
            'old_password' => ['required', 'string', 'min:8'],
            'password' => ['required', 'confirmed', 'string', 'min:6', 'regex:/^[A-Za-z][A-Za-z0-9@$!%*?&#]*[@$!%*?&#]+[A-Za-z0-9@$!%*?&#]*$/']
        ];
    }
}
