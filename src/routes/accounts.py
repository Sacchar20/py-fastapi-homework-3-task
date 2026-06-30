from datetime import datetime, timezone
from typing import cast

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import delete, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from config import BaseAppSettings, get_jwt_auth_manager, get_settings
from database import (
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel,
    UserGroupEnum,
    UserGroupModel,
    UserModel,
    get_db,
)
from exceptions import BaseSecurityError
from schemas.accounts import (
    MessageResponseSchema,
    PasswordResetCompleteRequestSchema,
    PasswordResetRequestSchema,
    TokenRefreshRequestSchema,
    TokenRefreshResponseSchema,
    UserActivationRequestSchema,
    UserLoginRequestSchema,
    UserLoginResponseSchema,
    UserRegistrationRequestSchema,
    UserRegistrationResponseSchema,
)
from security.interfaces import JWTAuthManagerInterface

router = APIRouter()


@router.post(
    "/register/",
    status_code=status.HTTP_201_CREATED,
    response_model=UserRegistrationResponseSchema,
)
async def register_user(
    user_data: UserRegistrationRequestSchema,
    db: AsyncSession = Depends(get_db),
) -> UserRegistrationResponseSchema:
    existing_user = (
        await db.execute(select(UserModel).where(UserModel.email == user_data.email))
    ).scalar_one_or_none()

    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A user with this email {user_data.email} already exists.",
        )

    try:
        user_group = (
            await db.execute(
                select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER)
            )
        ).scalar_one()

        user = UserModel.create(
            email=str(user_data.email),
            raw_password=user_data.password,
            group_id=user_group.id,
        )
        db.add(user)
        await db.flush()

        activation_token = ActivationTokenModel(user_id=user.id)
        db.add(activation_token)

        await db.commit()
        await db.refresh(user)
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation.",
        )

    return user


@router.post(
    "/activate/",
    status_code=status.HTTP_200_OK,
    response_model=MessageResponseSchema,
)
async def activate_user_account(
    activation_data: UserActivationRequestSchema,
    db: AsyncSession = Depends(get_db),
) -> MessageResponseSchema:
    user = (
        await db.execute(select(UserModel).where(UserModel.email == activation_data.email))
    ).scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token.",
        )

    if user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User account is already active.",
        )

    token_record = (
        await db.execute(
            select(ActivationTokenModel).where(
                ActivationTokenModel.user_id == user.id,
                ActivationTokenModel.token == activation_data.token,
            )
        )
    ).scalar_one_or_none()

    if not token_record:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token.",
        )

    expires_at = cast(datetime, token_record.expires_at).replace(tzinfo=timezone.utc)
    if expires_at < datetime.now(tz=timezone.utc):
        await db.execute(
            delete(ActivationTokenModel).where(ActivationTokenModel.id == token_record.id)
        )
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token.",
        )

    user.is_active = True
    await db.execute(
        delete(ActivationTokenModel).where(ActivationTokenModel.id == token_record.id)
    )
    await db.commit()

    return MessageResponseSchema(message="User account activated successfully.")


@router.post(
    "/password-reset/request/",
    status_code=status.HTTP_200_OK,
    response_model=MessageResponseSchema,
)
async def request_password_reset(
    reset_data: PasswordResetRequestSchema,
    db: AsyncSession = Depends(get_db),
) -> MessageResponseSchema:
    success_response = MessageResponseSchema(
        message="If you are registered, you will receive an email with instructions."
    )

    user = (
        await db.execute(select(UserModel).where(UserModel.email == reset_data.email))
    ).scalar_one_or_none()

    if not user or not user.is_active:
        return success_response

    await db.execute(
        delete(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == user.id)
    )

    reset_token = PasswordResetTokenModel(user_id=user.id)
    db.add(reset_token)
    await db.commit()

    return success_response


@router.post(
    "/reset-password/complete/",
    status_code=status.HTTP_200_OK,
    response_model=MessageResponseSchema,
)
async def complete_password_reset(
    reset_data: PasswordResetCompleteRequestSchema,
    db: AsyncSession = Depends(get_db),
) -> MessageResponseSchema:
    user = (
        await db.execute(select(UserModel).where(UserModel.email == reset_data.email))
    ).scalar_one_or_none()

    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token.",
        )

    token_record = (
        await db.execute(
            select(PasswordResetTokenModel).where(
                PasswordResetTokenModel.user_id == user.id,
            )
        )
    ).scalar_one_or_none()

    if not token_record:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token.",
        )

    if token_record.token != reset_data.token:
        await db.execute(
            delete(PasswordResetTokenModel).where(PasswordResetTokenModel.id == token_record.id)
        )
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token.",
        )

    expires_at = cast(datetime, token_record.expires_at).replace(tzinfo=timezone.utc)
    if expires_at < datetime.now(tz=timezone.utc):
        await db.execute(
            delete(PasswordResetTokenModel).where(PasswordResetTokenModel.id == token_record.id)
        )
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token.",
        )

    try:
        user.set_password(reset_data.password)

        await db.execute(
            delete(PasswordResetTokenModel).where(PasswordResetTokenModel.id == token_record.id)
        )
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while resetting the password.",
        )

    return MessageResponseSchema(message="Password reset successfully.")


@router.post(
    "/login/",
    status_code=status.HTTP_201_CREATED,
    response_model=UserLoginResponseSchema,
)
async def login_user(
    login_data: UserLoginRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
    settings: BaseAppSettings = Depends(get_settings),
) -> UserLoginResponseSchema:
    user = (
        await db.execute(select(UserModel).where(UserModel.email == login_data.email))
    ).scalar_one_or_none()

    if not user or not user.verify_password(login_data.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is not activated.",
        )

    try:
        user_id = user.id
        access_token = jwt_manager.create_access_token({"user_id": user_id})
        refresh_token = jwt_manager.create_refresh_token({"user_id": user_id})

        token_record = RefreshTokenModel.create(
            user_id=user_id,
            days_valid=settings.LOGIN_TIME_DAYS,
            token=refresh_token,
        )
        db.add(token_record)
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request.",
        )

    return UserLoginResponseSchema(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
    )


@router.post(
    "/refresh/",
    status_code=status.HTTP_200_OK,
    response_model=TokenRefreshResponseSchema,
)
async def refresh_access_token(
    refresh_data: TokenRefreshRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
) -> TokenRefreshResponseSchema:
    try:
        payload = jwt_manager.decode_refresh_token(refresh_data.refresh_token)
    except BaseSecurityError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        )

    user_id: int = payload.get("user_id")

    token_record = (
        await db.execute(
            select(RefreshTokenModel).where(
                RefreshTokenModel.token == refresh_data.refresh_token
            )
        )
    ).scalar_one_or_none()

    if not token_record:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token not found.",
        )

    user = (
        await db.execute(select(UserModel).where(UserModel.id == user_id))
    ).scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found.",
        )

    new_access_token = jwt_manager.create_access_token({"user_id": user_id})

    return TokenRefreshResponseSchema(access_token=new_access_token)
